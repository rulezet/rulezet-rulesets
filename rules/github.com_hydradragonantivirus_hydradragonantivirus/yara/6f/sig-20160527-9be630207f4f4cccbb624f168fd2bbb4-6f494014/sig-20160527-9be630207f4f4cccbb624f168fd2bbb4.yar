rule sig_20160527_9be630207f4f4cccbb624f168fd2bbb4 {
  meta:
    description = "datamaliciousorder - file 20160527_9be630207f4f4cccbb624f168fd2bbb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bffe274fece91c83727fa86b482a2eaa6926ca0b06359c1bc0d61210e3b46da3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<asf2ue.length;i++)if(i%2==0)x.push(asf2ue[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}