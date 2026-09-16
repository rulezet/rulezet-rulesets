rule sig_20160527_ec949aa8e94eb1468cb00a43b85ed580 {
  meta:
    description = "datamaliciousorder - file 20160527_ec949aa8e94eb1468cb00a43b85ed580.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14c1c8d308b0da762ac0c22dcae7de57aa0cc5a1b526d33036b26685f2776086"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aCLE0dGeb.length;i++)if(i%2==0)x.push(aCLE0dGeb[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}