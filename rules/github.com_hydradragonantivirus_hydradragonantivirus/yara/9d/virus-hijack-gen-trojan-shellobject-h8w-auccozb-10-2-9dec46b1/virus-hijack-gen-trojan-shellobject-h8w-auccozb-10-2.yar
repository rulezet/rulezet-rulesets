rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_auCCoZb_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4aa82dbb65fb909d84bee0d7afc1e8fe095621cfbc4ca2963ae7e68d4608d14"

  strings:
    $s1  = "vLibreOffice, the office productivity suite provided by The Document Foundation. See https://www.documentfoundation.org6..\\.." wide
    $s2  = "if test \"`echo -n a`\" = \"-n a\"; then" fullword ascii
    $s3  = "if test \"$ANS\" = 'e' -o \"$ANS\" = 'q'; then" fullword ascii
    $s4  = "if test $? -eq 0 -a -n \"$oldtty\"; then" fullword ascii
    $s5  = "# adapted from zmore by Philippe Troin <phil@fifi.org> for Debian GNU/Linux." fullword ascii
    $s6  = "PATH=\"/usr/bin:$PATH\"; export PATH" fullword ascii
    $s7  = "echo \"------> $FILE <------\"" fullword ascii
    $s8  = "if test $FIRST -eq 0; then" fullword ascii
    $s9  = "# Bzmore wrapped for bzip2, " fullword ascii
    $s10 = "if stty -cbreak 2>/dev/null; then" fullword ascii
    $s11 = "if test -t; then" fullword ascii
    $s12 = "bzip2 -cdfq \"$FILE\" | eval $more" fullword ascii
    $s13 = "bzip2 -cdfq | eval $more" fullword ascii
    $s14 = "  # looks like a SysV system:" fullword ascii
    $s15 = "    if test -t 0; then" fullword ascii
    $s16 = "if test \"$ANS\" != 's'; then" fullword ascii
    $s17 = "echo $n1 \"--More--(Next file: $FILE)$n2\"" fullword ascii
    $s18 = "if test $# = 0; then" fullword ascii
    $s19 = "prog=`echo $0 | sed 's|.*/||'`" fullword ascii
    $s20 = "stty $ncb echo 2>/dev/null" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}