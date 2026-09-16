rule sig_20160527_e0f16a92ce285af6cb29d84c713e6416 {
  meta:
    description = "datamaliciousorder - file 20160527_e0f16a92ce285af6cb29d84c713e6416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3e3845f4b29fa8b0d5ee3f97aae4ad6fddd9a62eefde24aedfd5ee074f53bfb"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXhAeQR.length;i++)if(i%2==0)x.push(aXhAeQR[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}