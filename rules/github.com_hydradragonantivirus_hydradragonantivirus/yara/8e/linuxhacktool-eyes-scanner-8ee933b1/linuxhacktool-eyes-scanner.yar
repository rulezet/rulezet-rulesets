rule LinuxHacktool_eyes_scanner {
  meta:
    description = "Linux hack tools - file scanner"
    author      = "Florian Roth"
    reference   = "not set"
    date        = "2015/01/19"
    hash        = "5488698b7f9090f45096517e61768efd32299d5b"

  strings:
    $s0  = "%s: line %d: list delimiter not followed by keyword" fullword ascii
    $s1  = "checking for version `%s' in file %s required by file %s" fullword ascii
    $s3  = "%s: line %d: expected service, found `%s'" fullword ascii
    $s4  = "truncated dump file; tried to read %d header bytes, only got %lu" fullword ascii
    $s5  = "%s: line %d: list delimiter not followed by domain" fullword ascii
    $s7  = "'protochain' not supported with radiotap headers" fullword ascii
    $s8  = "%s(): unsuported injection type" fullword ascii
    $s9  = "ELF load command address/offset not properly aligned" fullword ascii
    $s10 = "@(#) $Header: /tcpdump/master/libpcap/gencode.c,v 1.221.2.27 2005/07/14 16:01:46" ascii
    $s20 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii

  condition:
    4 of them
}