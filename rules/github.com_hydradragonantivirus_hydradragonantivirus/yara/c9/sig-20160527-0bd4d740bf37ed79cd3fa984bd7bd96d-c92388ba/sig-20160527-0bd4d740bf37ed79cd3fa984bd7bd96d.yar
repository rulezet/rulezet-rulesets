rule sig_20160527_0bd4d740bf37ed79cd3fa984bd7bd96d {
  meta:
    description = "datamaliciousorder - file 20160527_0bd4d740bf37ed79cd3fa984bd7bd96d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f24fc59e477f5f443f69fed33d2869afa926f8cbe8cd56c4df1d58a7f93f3f8b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a0TN4rP45.length;i++)if(i%2==0)x.push(a0TN4rP45[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}