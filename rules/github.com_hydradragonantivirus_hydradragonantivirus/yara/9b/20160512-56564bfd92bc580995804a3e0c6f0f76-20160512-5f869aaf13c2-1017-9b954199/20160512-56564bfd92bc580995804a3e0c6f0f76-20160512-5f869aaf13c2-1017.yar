rule _20160512_56564bfd92bc580995804a3e0c6f0f76_20160512_5f869aaf13c2_1017 {
  meta:
    description = "datamaliciousorder - from files 20160512_56564bfd92bc580995804a3e0c6f0f76.js, 20160512_5f869aaf13c2d982341b22847791b6de.js, 20160512_6208973bd11f1b6cd43d57fc7f74473d.js, 20160512_7ba3b6f8b201065695c8c647022e4cf0.js, 20160512_868025f1324d752b4a8e093a44b58089.js, 20160512_c98ad01de208781e5ca28e937ba54732.js, 20160512_e1df49610cca8ef0016fe880c5a0ae3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23df210ab2592ede5b5653de30f25f596f84d19ea9be72b1bd38631fb0433844"
    hash2       = "432f80a98b0d100d186a286960fb547ba471690e560b61ce0bbf2ce3123b2fc0"
    hash3       = "7754ebc934cf4384051276042f2421d9939a83352b8920172ed097c0b4818d42"
    hash4       = "9884b59466a1413b227a1d3155e672213edc697dda6e67aac24abe3e13f96f70"
    hash5       = "ef574d78ea0732549e34b9a11cad7a28c5bdb8bdd9ba05346f1a2d48b569609b"
    hash6       = "fc8f5f709784e178b21ba9157f13c6f75ae855bb8030a4935d51f7e3fedd3509"
    hash7       = "9b0d77f1114b4ca7e71364155fb15f6c8fee0f669fb08694f5088cd2246bb7b9"

  strings:
    $s1 = "undesirable = undesirable+ pushmenow.shift();" fullword ascii
    $s2 = "var inauspicious = pushmenow.pop().split(\"" fullword ascii
    $s3 = "String.prototype.helperFut2 = function () {" fullword ascii
    $s4 = "String.prototype.helperFut = function () {" fullword ascii
    $s5 = "String.prototype.helperFut4 = function() {" fullword ascii
    $s6 = "var offense = this[pushmenow.shift()];" fullword ascii
    $s7 = "var prelude = leasing[pushmenow.shift()](pushmenow.shift());" fullword ascii

  condition:
    (uint16(0) == 0x6c4b and (all of them)
    ) or (all of them)
}