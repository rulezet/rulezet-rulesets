rule sig_20160527_5103a9f662a7e18df9585fa955f91d2a {
  meta:
    description = "datamaliciousorder - file 20160527_5103a9f662a7e18df9585fa955f91d2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa86295e5cefa9c18e29d11d140cb68371507ba525c53122794ff6c6e20f7858"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a2Rwtyv.length;i++)if(i%2==0)x.push(a2Rwtyv[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}