rule Hacktools_CN_Panda_andrew {
  meta:
    description = "Disclosed hacktool set - file andrew.exe - sethc.exe Debugger backdoor"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "abd03ebb08314297b83e6c795cc85bb85e1f4d71"

  strings:
    $s0  = "(http://www.eyuyan.com)" fullword wide
    $s1  = "ClosePrinter" fullword ascii
    $s18 = "version=\"1.0\" encoding" fullword ascii

  condition:
    all of them
}