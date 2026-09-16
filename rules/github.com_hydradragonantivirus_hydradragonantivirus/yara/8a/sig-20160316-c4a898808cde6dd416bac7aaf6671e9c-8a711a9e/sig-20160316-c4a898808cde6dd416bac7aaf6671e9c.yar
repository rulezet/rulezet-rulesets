rule sig_20160316_c4a898808cde6dd416bac7aaf6671e9c {
  meta:
    description = "datamaliciousorder - file 20160316_c4a898808cde6dd416bac7aaf6671e9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "380f45741f14a155a92a2438ef17e9df2cdf06a5e502a73dbd4ee5f29f707d7d"

  strings:
    $s1 = "while (LNHG[bIqtoHdOkkAhIs + rrLPNjdi + GYwulPVLHY + KvWvjttRVM + irCHmKwoTklf + SuHDcO + SZZQDdXlkffrwkH] < 4 ) {WScript[nfmTjX" ascii
    $s2 = "while (LNHG[bIqtoHdOkkAhIs + rrLPNjdi + GYwulPVLHY + KvWvjttRVM + irCHmKwoTklf + SuHDcO + SZZQDdXlkffrwkH] < 4 ) {WScript[nfmTjX" ascii
    $s3 = "LNHG[ryvMTCqAPyxCiBk + pPtuWlwcwOo + xHnzFsSddsYnub](ICrvNp + oELXauIUVYzkk, IycWTOKRRdKQ + xjFk + tpdOEBVcjhT + Ytnup + TQDfywx" ascii
    $s4 = "function JxGnWom(n){return QgyYREBen + oqiLdn + nwiahOtWthJcGyR + XevmNk + WGA + ScfLY + cwBBLqxj + eUkjFBlYJ;}" fullword ascii
    $s5 = "function YMQNpiO(dyAJUS){mblo[egF + pKXLWkRzxTJJt](dyAJUS, 0, 0);}" fullword ascii
    $s6 = "odFs, false);" fullword ascii
    $s7 = "var wAAwT = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}