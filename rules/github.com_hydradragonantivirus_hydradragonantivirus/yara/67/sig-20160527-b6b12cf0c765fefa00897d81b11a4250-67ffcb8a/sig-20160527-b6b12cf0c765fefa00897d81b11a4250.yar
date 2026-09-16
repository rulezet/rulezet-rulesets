rule sig_20160527_b6b12cf0c765fefa00897d81b11a4250 {
  meta:
    description = "datamaliciousorder - file 20160527_b6b12cf0c765fefa00897d81b11a4250.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12e695a86ae4b1598c91620282cbfabb592d3590389fd63ebc5d37df3ece502e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aLVjpfyfjq.length;i++)if(i%2==0)x.push(aLVjpfyfjq[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}