rule sig_20160527_0110f9d9f68db195ffd27077395b7bf4 {
  meta:
    description = "datamaliciousorder - file 20160527_0110f9d9f68db195ffd27077395b7bf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b085d382391971d1bd5d363251a44ef6ea2db85478d45a76b2efb005f6083b18"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<au9yPpFL.length;i++)if(i%2==0)x.push(au9yPpFL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}