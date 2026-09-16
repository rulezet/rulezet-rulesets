rule sig_20160527_8b4daccec2032ba76e19103b2cec284a {
  meta:
    description = "datamaliciousorder - file 20160527_8b4daccec2032ba76e19103b2cec284a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "674b05440591eaf7d6c022f5c796b6cab4359e658da0849839a4adb4e3c6b0df"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aliW2NoT.length;i++)if(i%2==0)x.push(aliW2NoT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}