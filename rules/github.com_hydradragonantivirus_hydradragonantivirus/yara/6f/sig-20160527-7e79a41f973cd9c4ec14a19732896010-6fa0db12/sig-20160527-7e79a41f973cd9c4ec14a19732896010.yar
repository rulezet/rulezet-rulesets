rule sig_20160527_7e79a41f973cd9c4ec14a19732896010 {
  meta:
    description = "datamaliciousorder - file 20160527_7e79a41f973cd9c4ec14a19732896010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d2e962f368edf7e29488ba6f63e8bf1b9c7325d74ab63e78fe775d0627d6fb5"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aTZhcJ.length;i++)if(i%2==0)x.push(aTZhcJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}