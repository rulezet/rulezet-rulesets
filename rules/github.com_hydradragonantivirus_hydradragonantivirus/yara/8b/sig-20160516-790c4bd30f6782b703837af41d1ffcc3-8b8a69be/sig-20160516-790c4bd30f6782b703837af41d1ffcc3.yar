rule sig_20160516_790c4bd30f6782b703837af41d1ffcc3 {
  meta:
    description = "datamaliciousorder - file 20160516_790c4bd30f6782b703837af41d1ffcc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a01bc20855449df1ea6304db217cf54b1526ca177fdfd8fb5630d272f3f380a"

  strings:
    $s1 = "var bvquw='vmvne2appqylrulcjk a2qorezey3auyulnycvatljjq13lyuy4kunzjooodtrplfrjmemcv=la1ep\\'q4qmptjat3zcv2ozqnbgfgpiu2xndfb3hugu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}