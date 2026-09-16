rule Hacktools_CN_JoHor_Rdos {
  meta:
    description = "Disclosed hacktool set - file spec.vbp"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "400a90c9eabeb94ae05e5036e21dc922b0c1ffad"

  strings:
    $s3  = "service@dywt.com.cn" fullword ascii
    $s9  = "www.dywt.com.cn" fullword ascii
    $s17 = "This is a runtime library file for EPL applications. The EPL is a software devel" ascii

  condition:
    2 of them
}