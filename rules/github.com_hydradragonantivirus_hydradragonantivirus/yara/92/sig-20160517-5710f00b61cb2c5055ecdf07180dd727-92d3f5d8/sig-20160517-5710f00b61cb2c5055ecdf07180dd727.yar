rule sig_20160517_5710f00b61cb2c5055ecdf07180dd727 {
  meta:
    description = "datamaliciousorder - file 20160517_5710f00b61cb2c5055ecdf07180dd727.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b70ffd71d20304956a0adcaf8019d910344f6365fd958ef152df22c6fd0e08d"

  strings:
    $s1 = "var d2gsqm='vlspsuasvjxnrejul4 qpafbwfb14xvdc4vkvbmctebtdalacscnnrnorhv2adkdnobhtuepbmiblchpmjp2=zheby\\'twqhrtuybzmcz4goinaxuai" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}