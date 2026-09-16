rule sig_20170221_61b5bffa047bf19266476b0809a13d20 {
  meta:
    description = "datamaliciousorder - file 20170221_61b5bffa047bf19266476b0809a13d20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3cff7fe359dfd4c69ad2b80f157586d3d1e619bcbf8e5d8e2547194dae3e34"

  strings:
    $s1 = "var x = new Array(\"b-sig.com\", \"mana.whitespaceco.com\", \"powerofattorney-online-form.com\", \"espacoorleans.com.br\", \"bry" ascii
    $s2 = "var x = new Array(\"b-sig.com\", \"mana.whitespaceco.com\", \"powerofattorney-online-form.com\", \"espacoorleans.com.br\", \"bry" ascii
    $s3 = "lt0e_22ek90l8XnM0\"; try { x[i] = z9+x[i]+z10; e.open(z8 + z6, x[i]+m, false); e.send(); var z3 = e.responseText; if (z3.length " ascii
    $s4 = " 1000) { if (z3.indexOf(m) > -1) { var z3 = z3.split(m); var z3 = z3.join(z4); eval(z3); break; }; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}