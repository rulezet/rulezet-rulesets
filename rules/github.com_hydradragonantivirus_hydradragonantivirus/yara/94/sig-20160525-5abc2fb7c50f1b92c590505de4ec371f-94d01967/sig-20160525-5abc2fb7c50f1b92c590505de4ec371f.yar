rule sig_20160525_5abc2fb7c50f1b92c590505de4ec371f {
  meta:
    description = "datamaliciousorder - file 20160525_5abc2fb7c50f1b92c590505de4ec371f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff28e321b3633de000adc03811371062e48ee8b1f4855cd22b520c326bd8c581"

  strings:
    $s1 = "l noitcnuf\\n;\"27x\\\\w\" = rerednerl rav\\n;\"et96x\\\\\" = iml rav\\n;\"s56x\\\\R\" = eixodm rav\\n;\"se6x\\\\op\" = gsmm rav" ascii
    $s2 = "rav\\n;\"er34x\\\\\" = eixodf rav\\n;\"e47x\\\\a\" = gsmf rav\\n;\"26x\\\\O\" = suidarelcitrapf rav\\n;\"cea6x\\\\\" = dnenoisil" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}