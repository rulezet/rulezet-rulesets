rule sig_20160527_d35a61b64eb5d0c87c278f6beb95a08d {
  meta:
    description = "datamaliciousorder - file 20160527_d35a61b64eb5d0c87c278f6beb95a08d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0fb560d10621a550e0fbcc99cd3e3c423d5997227eee66671396b11cfbe315c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aA9a3AgSgR.length;i++)if(i%2==0)x.push(aA9a3AgSgR[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}