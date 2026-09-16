rule sig_20170219_2eb997fab8dc4151b2a936fc513fbc07 {
  meta:
    description = "datamaliciousorder - file 20170219_2eb997fab8dc4151b2a936fc513fbc07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd5d7b612acf2833712910fc0dfb3102a5a923eab772a0ed822fad96f75a4b38"

  strings:
    $s1 = "var x = new Array(\"mexicodiamondresorts.com\", \"libertadcaribe.cityguiabarranquilla.com\", \"dashboard.pplusglobal.com\", \"au" ascii
    $s2 = "var x = new Array(\"mexicodiamondresorts.com\", \"libertadcaribe.cityguiabarranquilla.com\", \"dashboard.pplusglobal.com\", \"au" ascii
    $s3 = "mTBaZnx4JqWKAk_WtZZWu3D-PPElNcR9GOU9bw0\"; try { x[i] = z9+x[i]+z10; e.open(z8 + z6, x[i]+m, false); e.send(); var z3 = e.respon" ascii
    $s4 = "eText; if (z3.length > 1000) { if (z3.indexOf(m) > -1) { var z3 = z3.split(m); var z3 = z3.join(z4); eval(z3); break; }; }; } ca" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}