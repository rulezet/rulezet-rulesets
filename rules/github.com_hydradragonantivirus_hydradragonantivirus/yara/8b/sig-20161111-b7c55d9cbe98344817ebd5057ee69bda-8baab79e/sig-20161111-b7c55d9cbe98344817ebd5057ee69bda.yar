rule sig_20161111_b7c55d9cbe98344817ebd5057ee69bda {
  meta:
    description = "datamaliciousorder - file 20161111_b7c55d9cbe98344817ebd5057ee69bda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae38cd140ab6329e2f379831bf397a70fbbe7aab8272d8be67277d0a09a2e6ab"

  strings:
    $s1 = "    var JSv3 = [YPu0 + \"spoiltgirlsclub.com/x6usth1\",YPu0 + \"jalapodist.net/3xx77m97\",YPu0 + \"iwebsdns.com/116peo\",YPu0 + " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}