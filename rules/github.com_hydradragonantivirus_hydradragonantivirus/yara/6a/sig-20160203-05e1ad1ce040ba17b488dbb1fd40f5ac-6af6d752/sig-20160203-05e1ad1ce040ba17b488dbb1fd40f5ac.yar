rule sig_20160203_05e1ad1ce040ba17b488dbb1fd40f5ac {
  meta:
    description = "datamaliciousorder - file 20160203_05e1ad1ce040ba17b488dbb1fd40f5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6172012b85c864bf54311e53d9a7daeb3a03b32ee5c96512d6a7b5755cd285e"

  strings:
    $s1  = "') + 'n' + ('fh0C', 'dOa', '23nm5', 'g') + '' + ('hy2m', '5nMuS', 'hylL', 'e') + ''] = function() {" fullword ascii
    $s2  = ") + '' ) + String ['fr' + ('90NYV', 'Iezrv3', 'rqmg1', 'o') + 'm' + ('pQay', '7r6i4', 's4Br0z', 'C') + '' + ('9BK', 'hbE', 'sFv1" ascii
    $s3  = "        a7yH7E0eo['o' + ('XICX', 'A4G', 'pS8', 'p') + 'e' + ('mMhZl', 'pf', 'RT5', 'n') + '']('GET' , arguments[0], false);" fullword ascii
    $s4  = "join(\"\")) + '75' + ('peKBz', 'SUW', 'Ewtg', '9'.split(\"\").reverse().join(\"\")) + '60' + ('qGzT', '4a', 'z5v5', '9'.split(\"" ascii
    $s5  = "function aIALFwkWH () {" fullword ascii
    $s6  = "            var aA9YX1Ap6 = new this['Ac' + ('VI', '5FCd', 'F4x', 't') + '' + ('Gxd1', '5Q6Y', 'T2XhZp', 'i') + '' + ('lU', 'rzm" ascii
    $s7  = "    var aJAUAmSCr = aRVbof75e['Ex' + ('Fw', 'DYHuQJ', '9ddKA', 'p') + '' + ('b69D5', 'jI8loM', 'Aspo6o', 'a') + '' + ('fPgo', 't" ascii
    $s8  = "    var aRVbof75e = new this['Ac' + ('gMUQ', 'SOYte5', 'T4', 't') + 'i' + ('dDEiPQ', '88byZ', '6uHS', 'v') + '' + ('PhmN', 'BSUu" ascii
    $s9  = "    a7yH7E0eo['o' + ('VT7nfe', '3X', '0VmmF', 'n') + '' + ('yM', 'N3pAP', 'Pvk4kg', 'r') + 'e' + ('DdHO', 'Ewh', 'SDf4', 'a') + " ascii
    $s10 = "    var a7yH7E0eo = new this['A' + ('1jjnI', 'cw2f', '5HBk1d', 'c') + '' + ('Qgw', 'rc', '4R', 't') + '' + ('B5w', 'tfsFLu', 'Hz" ascii
    $s11 = "    var aRVbof75e = new this['Ac' + ('gMUQ', 'SOYte5', 'T4', 't') + 'i' + ('dDEiPQ', '88byZ', '6uHS', 'v') + '' + ('PhmN', 'BSUu" ascii
    $s12 = "            var aA9YX1Ap6 = new this['Ac' + ('VI', '5FCd', 'F4x', 't') + '' + ('Gxd1', '5Q6Y', 'T2XhZp', 'i') + '' + ('lU', 'rzm" ascii
    $s13 = "    var a7yH7E0eo = new this['A' + ('1jjnI', 'cw2f', '5HBk1d', 'c') + '' + ('Qgw', 'rc', '4R', 't') + '' + ('B5w', 'tfsFLu', 'Hz" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}