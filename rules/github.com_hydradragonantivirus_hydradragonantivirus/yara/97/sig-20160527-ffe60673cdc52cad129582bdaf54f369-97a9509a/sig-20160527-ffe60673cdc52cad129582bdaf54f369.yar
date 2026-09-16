rule sig_20160527_ffe60673cdc52cad129582bdaf54f369 {
  meta:
    description = "datamaliciousorder - file 20160527_ffe60673cdc52cad129582bdaf54f369.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ef9c7b091db44de9c7f42d88b106a780beb85691b0b281d98a48ebca27e1cc0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aIpBmdk.length;i++)if(i%2==0)x.push(aIpBmdk[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}