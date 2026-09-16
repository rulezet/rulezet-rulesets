rule sig_20160203_73f26d2f349cd67f0f73367ab89f3f92 {
  meta:
    description = "datamaliciousorder - file 20160203_73f26d2f349cd67f0f73367ab89f3f92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be880892d278e86beab367780fcb480555a76ef5cfa474be5e6baa3aa6b78a04"

  strings:
    $s1  = "reverse().join(\"\")) + 'ML' + ('WSlO', '7q', 'tWS1q', '2'.split(\"\").reverse().join(\"\")) + '.X' + ('omhIZl', 'i7k', 'xG', 'M" ascii
    $s2  = "6aseS', 'Msz', 'JMii7', 'g') + 'e'] = function() {" fullword ascii
    $s3  = "join(\"\")) + '3' + ('WMk', 'Yb', 'APA', 'r'.split(\"\").reverse().join(\"\")) + 'f' + ('lT1bJ', 'Puu', 'OPL', '3'.split(\"\").r" ascii
    $s4  = ".join(\"\")) + 'M' + ('4hTg8z', 'YovO', 'NYn', 'P'.split(\"\").reverse().join(\"\")) + '%' ) + String ['f' + ('KYj', 'KF17', '5n" ascii
    $s5  = "function awXztawsa () {" fullword ascii
    $s6  = " '' , arguments[0], false);" fullword ascii
    $s7  = "        aluIYkrZ0['op' + ('lXwYgW', '84Oj4i', 'IDv', 'e') + 'n']('GE' + ('LHp', 'fCT', 'SB', 'T'.split(\"\").reverse().join(\"\"" ascii
    $s8  = "            var aeACpodRw = new this['Ac' + ('uOn7', '3k3N', 'sY0cR', 't') + 'i' + ('uezm', 'ev', 'I9i', 'v') + 'e' + ('QmLeub'," ascii
    $s9  = "    aluIYkrZ0['on' + ('qbH', 'NyiS', 'XYA', 'r') + '' + ('dW4yBB', 'zg', 'ys', 'e') + 'a' + ('Ojt', 'ubK', 'J3a', 'd') + '' + ('" ascii
    $s10 = "    var aluIYkrZ0 = new this['A' + ('lrz', 'Ih', 'vvtkZ0', 'c') + '' + ('xaWD8t', 'UPYVU', 'vj3QKD', 't') + '' + ('VUYq', 'jqp'," ascii
    $s11 = "    var aluIYkrZ0 = new this['A' + ('lrz', 'Ih', 'vvtkZ0', 'c') + '' + ('xaWD8t', 'UPYVU', 'vj3QKD', 't') + '' + ('VUYq', 'jqp'," ascii
    $s12 = "    var aRFy2b1c4 = new this['Ac' + ('GROVsr', 'QEb', 'XaS', 't') + 'i' + ('tO', 'JkzbT', 'IN3X', 'v') + 'e' + ('DxGzZ7', 'QM5dK" ascii
    $s13 = "    var aRFy2b1c4 = new this['Ac' + ('GROVsr', 'QEb', 'XaS', 't') + 'i' + ('tO', 'JkzbT', 'IN3X', 'v') + 'e' + ('DxGzZ7', 'QM5dK" ascii
    $s14 = "            var aeACpodRw = new this['Ac' + ('uOn7', '3k3N', 'sY0cR', 't') + 'i' + ('uezm', 'ev', 'I9i', 'v') + 'e' + ('QmLeub'," ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}