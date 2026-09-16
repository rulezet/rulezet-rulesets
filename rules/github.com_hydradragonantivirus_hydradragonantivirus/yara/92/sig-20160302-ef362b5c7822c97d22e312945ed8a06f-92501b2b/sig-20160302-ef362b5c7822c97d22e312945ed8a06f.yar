rule sig_20160302_ef362b5c7822c97d22e312945ed8a06f {
  meta:
    description = "datamaliciousorder - file 20160302_ef362b5c7822c97d22e312945ed8a06f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6429223e14f4a62591a975d6be391f6bc99c763f4837af4ebb50a13c94eb8f"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var grandiloquentjni = function() {" fullword ascii
    $s3 = "var gravityVUq = function(r) {" fullword ascii
    $s4 = "    var v = String[\"f\" + \"r\" + \"om\" + \"C\" + \"ha\" + \"rCode\"];" fullword ascii
    $s5 = "        decode: C," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}