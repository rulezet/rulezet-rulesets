rule sig_20160314_88fa77e34ec82003a46693deac80bd7e {
  meta:
    description = "datamaliciousorder - file 20160314_88fa77e34ec82003a46693deac80bd7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce76b8055e6f8c935c31a6a7cb2ebc9fd77e45bc80616468d203bd1e028a3f07"

  strings:
    $s1 = "while (tuVhm.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return bHEpLunjRr + HSchzkqMQgsVwR + TQTvjHJwJ + OQMtqVyundsEFM + KXTp + jZvqnEkWXG + kJatPmlCb" fullword ascii
    $s3 = "tuVhm.open(cQnenBleW + jpyCAV, lJRLnADfyZWWMt + lWGukiXFXnDPt + ffauspUC + TDNibAow + ZfHYyUUaoWHnKHr + Vpn + JcqwdmkzZQRkYxg + " ascii
    $s4 = "function nPBQEg(n)" fullword ascii
    $s5 = "function MQBNHqRUJLbqqe(fname)" fullword ascii
    $s6 = "DFpOiJjVsAgKqHv, false);" fullword ascii
    $s7 = "var nMBvSHzhne = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}