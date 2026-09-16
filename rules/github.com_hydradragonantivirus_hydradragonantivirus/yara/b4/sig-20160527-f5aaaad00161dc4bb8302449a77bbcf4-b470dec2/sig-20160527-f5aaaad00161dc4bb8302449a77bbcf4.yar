rule sig_20160527_f5aaaad00161dc4bb8302449a77bbcf4 {
  meta:
    description = "datamaliciousorder - file 20160527_f5aaaad00161dc4bb8302449a77bbcf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb4f4c96a5c26a8c21bab8a1f6026d96435bbc007879b6f0b1809fb07ca5d706"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aBGksgNp.length;i++)if(i%2==0)x.push(aBGksgNp[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}