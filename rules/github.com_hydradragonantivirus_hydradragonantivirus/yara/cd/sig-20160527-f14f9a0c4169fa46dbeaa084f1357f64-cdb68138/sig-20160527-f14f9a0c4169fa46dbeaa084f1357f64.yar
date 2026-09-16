rule sig_20160527_f14f9a0c4169fa46dbeaa084f1357f64 {
  meta:
    description = "datamaliciousorder - file 20160527_f14f9a0c4169fa46dbeaa084f1357f64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64c6a5ec2dbc577f84a8f88da0bd36d000d6e0407a4cae38e052944da4cc444"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aCKIgB.length;i++)if(i%2==0)x.push(aCKIgB[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}