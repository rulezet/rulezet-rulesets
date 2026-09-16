import "pe"
rule case_4778_1a5f3ca6597fcccd3295ead4d22ce70b {
  meta:
    description = "files - file 1a5f3ca6597fcccd3295ead4d22ce70b.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-08-15"
    hash1       = "7501da197ff9bcd49198dce9cf668442b3a04122d1034effb29d74e0a09529d7"

  strings:
    $s1  = "addconsole.dll" fullword wide
    $s2  = "C:\\Wrk\\mFiles\\86\\1\\Release\\addconsole.pdb" fullword ascii
    $s3  = ">->3>D>}>" fullword ascii  
    $s4  = "kmerjgyuhwjvueruewghgsdpdeo" fullword ascii
    $s5  = "~DMUlA].JVJ,[2^>O" fullword ascii
    $s6  = "xgF.lxh" fullword ascii
    $s7  = "2.0.0.11" fullword wide
    $s8  = "aripwx" fullword ascii
    $s9  = "YwTjoq1" fullword ascii
    $s10 = "LxDgEm0" fullword ascii
    $s11 = "rvrpsn" fullword ascii
    $s12 = "qb\"CTUAA~." fullword ascii
    $s13 = ":,7;\"/1/= 1!'4'(&*?/:--(-(!1(&9JVJVMO\\JBSBS[UBT_JHC@GLZMA\\QKUKVj{oi~m~ppeqdww~{bk" fullword ascii
    $s14 = ":,(9,=1?$2%06=:=*<'+2?!?-00!17$7XVZO_J]]X]XQAXVIZFZF]_LZRCRCKERDozxspw|j}qla{e{fzk" fullword ascii
    $s15 = "Time New Roman" fullword ascii
    $s16 = "gL:hdwKR8T" fullword ascii
    $s17 = "NwQvL?_" fullword ascii
    $s18 = "TEAqQ>W/" fullword ascii
    $s19 = "+mnHy<m8" fullword ascii
    $s20 = "uTVWh-F@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "ae9182174b5c4afd59b9b6502df5d8a1" or 8 of them)
}