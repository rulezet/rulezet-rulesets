rule Hacktools_CN_JoHor_Rdos_LineExp {
  meta:
    description = "Disclosed hacktool set - file LineExp.vbp"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "1bd2db477c68cdcba9ae5c3668bd76c51fc12d2e"

  strings:
    $s0 = "http://dywt.com.cn" fullword ascii
    $s1 = "service@dywt.com.cn" fullword ascii
    $s2 = "EThread.fne" fullword ascii
    $s3 = "GetNewInf" fullword ascii
    $s4 = "This is a runtime library file for EPL applications. The EPL is a software devel" ascii
    $s5 = "CloseThreadHandle" fullword ascii
    $s6 = "WaitThread" fullword ascii
    $s8 = "CreateCriticalSection" fullword ascii

  condition:
    all of them
}