rule sig_20160203_b850841fdd73e17be1aeae25a482eb25 {
  meta:
    description = "datamaliciousorder - file 20160203_b850841fdd73e17be1aeae25a482eb25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "493f0c92dfd74bae8007eeecd34ac6154182c6ee0c32fb4bad425e1ca05b3918"

  strings:
    $s1  = "print ('ht' + ('2iI', 'R0', 'cv6Qky', 't'.split(\"\").reverse().join(\"\")) + 'p' + ('Q1U7', 'KL8', 'EXg', ':'.split(\"\").rever" ascii
    $s2  = " String ['fr' + ('AKN', 'V8j8pn', 'pm768', 'o') + 'm' + ('n4TAj', 'kMAD', 'tQW', 'C') + '' + ('V9Meh', 'CT', 'Y0G7', 'h') + 'a' " ascii
    $s3  = "split(\"\").reverse().join(\"\")) + '.' + ('TZD7m4', 'KzjkF', '5Um0Tk', 's'.split(\"\").reverse().join(\"\")) + 'c' + ('EAjIG', " ascii
    $s4  = "reverse().join(\"\")) + 't' + ('Mgtht', 'AFT', 'zWp', 'r'.split(\"\").reverse().join(\"\")) + 'ea' + ('jaZ', 'X1U1', 'khyt', 'm'" ascii
    $s5  = ", 'Se', 'g') + '' + ('27', '9ASqF', 'gTEI', 'e') + ''] = function() {" fullword ascii
    $s6  = "s', 'T'.split(\"\").reverse().join(\"\")) + '' , arguments[0], false);" fullword ascii
    $s7  = "function ajS7QUTvD () {" fullword ascii
    $s8  = "print ('ht' + ('2iI', 'R0', 'cv6Qky', 't'.split(\"\").reverse().join(\"\")) + 'p' + ('Q1U7', 'KL8', 'EXg', ':'.split(\"\").rever" ascii
    $s9  = "    var a8lC2f7Fc = new this['A' + ('WA', '2KWT', 'gqv', 'c') + '' + ('jFHm', '7LHApD', 'gC4LU', 't') + '' + ('uFKfB', 'AS457', " ascii
    $s10 = "            var a5arRAjxa = new this['Ac' + ('gAPnum', 'gThZsP', 'VsC', 't') + 'i' + ('1Tk', 'qD1g', 'mSf', 'v') + 'e' + ('5ZXr'" ascii
    $s11 = "            var a5arRAjxa = new this['Ac' + ('gAPnum', 'gThZsP', 'VsC', 't') + 'i' + ('1Tk', 'qD1g', 'mSf', 'v') + 'e' + ('5ZXr'" ascii
    $s12 = "    var aEER3LpRG = a8lC2f7Fc['E' + ('Kjtw', 'L8so1', 'jl', 'x') + 'p' + ('cq4', 'xKk', 'gyRss', 'a') + 'n' + ('UAXo7', '9gcxh'," ascii
    $s13 = "    var a8lC2f7Fc = new this['A' + ('WA', '2KWT', 'gqv', 'c') + '' + ('jFHm', '7LHApD', 'gC4LU', 't') + '' + ('uFKfB', 'AS457', " ascii
    $s14 = "    a1eEjJrio['on' + ('1Qc1qA', 'D7Sw', 'o7o', 'r') + '' + ('aih2y', 'fn8mnM', 'nN', 'e') + 'a' + ('Pg9e', 'g7rEvy', 'Vk', 'd') " ascii
    $s15 = "    var a1eEjJrio = new this['Ac' + ('DT', 'rYBH', 'AkeH', 't') + 'i' + ('IAu', 'izr7e1', 'dY', 'v') + 'e' + ('UMmOd', 'NPvmpQ'," ascii
    $s16 = "    var a1eEjJrio = new this['Ac' + ('DT', 'rYBH', 'AkeH', 't') + 'i' + ('IAu', 'izr7e1', 'dY', 'v') + 'e' + ('UMmOd', 'NPvmpQ'," ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}