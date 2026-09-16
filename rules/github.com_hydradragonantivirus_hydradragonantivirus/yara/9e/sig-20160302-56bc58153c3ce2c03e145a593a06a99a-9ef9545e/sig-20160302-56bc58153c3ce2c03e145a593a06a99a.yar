rule sig_20160302_56bc58153c3ce2c03e145a593a06a99a {
  meta:
    description = "datamaliciousorder - file 20160302_56bc58153c3ce2c03e145a593a06a99a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24692b356cdac3232ba2a77b1d9a84a8eacdc7560b171c2d89dcd1d8397789b3"

  strings:
    $s1 = "var execratem2k = function() {" fullword ascii
    $s2 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s3 = "var homilyRqS = function(r) {" fullword ascii
    $s4 = "    var o = String[\"f\" + \"ro\" + \"mC\" + \"ha\" + \"rCode\"];" fullword ascii
    $s5 = "        decode: A," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}