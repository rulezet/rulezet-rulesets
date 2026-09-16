rule Hacktools_CN_JoHor_Rdos_3_6_uplis {
  meta:
    description = "Disclosed hacktool set - file uplis.vbp"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "a87d00d78838c2d968b72330ee6f21f69b2caae5"

  strings:
    $s0 = "http://dywt.com.cn" fullword ascii
    $s1 = "service@dywt.com.cn" fullword ascii
    $s4 = "GetNewInf" fullword ascii
    $s5 = "This is a runtime library file for EPL applications. The EPL is a software devel" ascii
    $s8 = "yiyuyan" fullword ascii

  condition:
    4 of them
}