rule sig_20160523_64d5be5e4d7f8f480d28272658a3ab2a {
  meta:
    description = "datamaliciousorder - file 20160523_64d5be5e4d7f8f480d28272658a3ab2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "287b17ae207757d9db5d10615a8c742ae1db59881d62350347f2361691b3f114"

  strings:
    $s1 = "reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}