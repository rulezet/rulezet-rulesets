rule sig_20160527_258962c1ead2edad874d43315fb2c6ab {
  meta:
    description = "datamaliciousorder - file 20160527_258962c1ead2edad874d43315fb2c6ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24ddc2b36886fd116727d373bbea4af41a1e8ab4e9be1cb303f349c25c8c1b65"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abyXh4HEj55.length;i++)if(i%2==0)x.push(abyXh4HEj55[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}