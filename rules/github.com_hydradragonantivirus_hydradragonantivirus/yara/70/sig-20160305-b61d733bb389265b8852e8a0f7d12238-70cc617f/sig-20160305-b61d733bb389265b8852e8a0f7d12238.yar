rule sig_20160305_b61d733bb389265b8852e8a0f7d12238 {
  meta:
    description = "datamaliciousorder - file 20160305_b61d733bb389265b8852e8a0f7d12238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfca3e3d499638237f6c2ca45165fc64ab136ef37ec32cfb1cd1c061d44b6f3a"

  strings:
    $s1 = "        return WScript[a](r);" fullword ascii
    $s2 = "var bulwarktoL = function(r) {" fullword ascii
    $s3 = "var rancorUUr = function() {" fullword ascii
    $s4 = "        return false === c.raw || c.utf8decode || e ? n.decode(r) : r;" fullword ascii
    $s5 = "        return r + \"====\".slice(r.length % 4 || 4);" fullword ascii
    $s6 = "    var f = String[\"f\" + \"ro\" + \"m\" + \"C\" + \"h\" + \"arCode\"];" fullword ascii
    $s7 = "        r = false === c.raw || c.utf8encode || a ? n.encode(r) : r;" fullword ascii
    $s8 = "        decode: function(r) {" fullword ascii
    $s9 = "    c.atob = c.decode = function(r, e) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}