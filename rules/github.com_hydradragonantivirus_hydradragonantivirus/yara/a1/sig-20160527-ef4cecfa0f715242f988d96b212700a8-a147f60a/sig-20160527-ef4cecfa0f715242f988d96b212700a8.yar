rule sig_20160527_ef4cecfa0f715242f988d96b212700a8 {
  meta:
    description = "datamaliciousorder - file 20160527_ef4cecfa0f715242f988d96b212700a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf8d63b850fac538208826885bfdf2c78904db298aab119b441ecf4b77783ff"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aACHbLV4eRT.length;i++)if(i%2==0)x.push(aACHbLV4eRT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}