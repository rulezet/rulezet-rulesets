rule sig_20160527_11ac039765ada9846fd3af72ef7a7b49 {
  meta:
    description = "datamaliciousorder - file 20160527_11ac039765ada9846fd3af72ef7a7b49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f60ca1c060957e84edfb7392736a815010e1bb8fafc0abbeec827f2e8dfffcf8"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ahNmIYhB.length;i++)if(i%2==0)x.push(ahNmIYhB[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}