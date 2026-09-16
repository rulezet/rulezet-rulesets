rule sig_20160527_6a5ad760503ba9f58450b0d9d63d7a2d {
  meta:
    description = "datamaliciousorder - file 20160527_6a5ad760503ba9f58450b0d9d63d7a2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb5fa5a3f536527752e58c888eca246d39836088f990d8c912faa8185c5fb634"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aO6a7uxD.length;i++)if(i%2==0)x.push(aO6a7uxD[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}