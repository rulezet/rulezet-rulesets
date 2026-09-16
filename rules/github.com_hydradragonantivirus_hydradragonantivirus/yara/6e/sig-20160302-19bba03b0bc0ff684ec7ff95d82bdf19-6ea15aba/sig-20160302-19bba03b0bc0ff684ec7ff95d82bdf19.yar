rule sig_20160302_19bba03b0bc0ff684ec7ff95d82bdf19 {
  meta:
    description = "datamaliciousorder - file 20160302_19bba03b0bc0ff684ec7ff95d82bdf19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2487b68fcf862c52bbc81e7ad54eded00be966ed5b06a1df4035b30b98235945"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var foiljfF = function() {" fullword ascii
    $s3 = "var fallowsY8 = function(r) {" fullword ascii
    $s4 = "    var u = String[\"f\" + \"r\" + \"o\" + \"m\" + \"Ch\" + \"arCode\"];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}