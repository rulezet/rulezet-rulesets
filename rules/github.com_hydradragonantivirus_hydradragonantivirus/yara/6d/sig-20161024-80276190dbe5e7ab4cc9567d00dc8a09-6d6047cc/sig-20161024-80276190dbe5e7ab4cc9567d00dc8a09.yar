rule sig_20161024_80276190dbe5e7ab4cc9567d00dc8a09 {
  meta:
    description = "datamaliciousorder - file 20161024_80276190dbe5e7ab4cc9567d00dc8a09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76bc923c42971bafa2afb54025aad2e9dcfb1077d23f0a8ef240bc55ba9b5d9a"

  strings:
    $s1 = "} while (ud++ < jr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}