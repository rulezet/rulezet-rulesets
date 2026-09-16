rule sig_20160302_bb0d5430cda16b7170e7dfa2611ff9ab {
  meta:
    description = "datamaliciousorder - file 20160302_bb0d5430cda16b7170e7dfa2611ff9ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34c9dd7eac1ace97ab6d8259a158c0fba38ebe3bff4ae4e08738e479b95fd971"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var vapidGfk = function(r) {" fullword ascii
    $s3 = "var esteemoAE = function() {" fullword ascii
    $s4 = "    var c = String[\"fr\" + \"omC\" + \"h\" + \"arCode\"];" fullword ascii
    $s5 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}