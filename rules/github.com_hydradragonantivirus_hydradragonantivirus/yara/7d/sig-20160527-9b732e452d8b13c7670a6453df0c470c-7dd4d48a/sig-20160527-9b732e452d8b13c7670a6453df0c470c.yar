rule sig_20160527_9b732e452d8b13c7670a6453df0c470c {
  meta:
    description = "datamaliciousorder - file 20160527_9b732e452d8b13c7670a6453df0c470c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71916b769085eadb7cffb02c11d31e1bd6637ca4b98cf9cde0ccc64b3336943f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a8TokorxD.length;i++)if(i%2==0)x.push(a8TokorxD[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}