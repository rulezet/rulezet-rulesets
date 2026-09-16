rule sig_20160330_dcff20bfe71041b1cb590869a02338e6 {
  meta:
    description = "datamaliciousorder - file 20160330_dcff20bfe71041b1cb590869a02338e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6defcd04c98158aa0419755c714410bf1d1a43eedaa3eca721f82651ea93d02"

  strings:
    $s1 = "while (KjqiYTd0LBX['' + ('hhvTl', '1jBT', 'rw'.a()) + 'e' + ('kQY_', 'e8kCQ', 'do', 'DrRc', 'ahAY'.a()) + ('M2zm_', 'ia', 'dK'.a" ascii
    $s2 = "while (KjqiYTd0LBX['' + ('hhvTl', '1jBT', 'rw'.a()) + 'e' + ('kQY_', 'e8kCQ', 'do', 'DrRc', 'ahAY'.a()) + ('M2zm_', 'ia', 'dK'.a" ascii
    $s3 = "function String.prototype.a() {return this.split('').reverse().pop();}" fullword ascii
    $s4 = "}catch(a72n9HKq60){};" fullword ascii
    $s5 = "}catch(YjqC68L) {};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}