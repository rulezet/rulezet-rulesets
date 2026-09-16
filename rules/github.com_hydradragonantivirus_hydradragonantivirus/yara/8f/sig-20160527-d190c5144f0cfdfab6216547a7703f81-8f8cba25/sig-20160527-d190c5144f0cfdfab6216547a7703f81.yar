rule sig_20160527_d190c5144f0cfdfab6216547a7703f81 {
  meta:
    description = "datamaliciousorder - file 20160527_d190c5144f0cfdfab6216547a7703f81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da0154c0eb5a3ef13d4dad1a8ed83344770276a0a3f212a42d72c05e60f29ca8"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ayQS7EJ9.length;i++)if(i%2==0)x.push(ayQS7EJ9[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}