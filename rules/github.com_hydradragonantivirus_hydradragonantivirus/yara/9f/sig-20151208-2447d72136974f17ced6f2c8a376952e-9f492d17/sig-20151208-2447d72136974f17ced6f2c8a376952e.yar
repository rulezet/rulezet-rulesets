rule sig_20151208_2447d72136974f17ced6f2c8a376952e {
  meta:
    description = "datamaliciousorder - file 20151208_2447d72136974f17ced6f2c8a376952e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b091a0520a7225bbe51e268abc24279d5ccc856fbc3d0c5c53c9a2805f1f1aa"

  strings:
    $s1 = "var str=\"5553565E0508010724011C1405101001070C4A070B095E275E0705100C1D000B00004A070B095E17565E5550505D5151535C545C5E55\";var m6=" ascii
    $s2 = "'}; }';var z8='eBod';function q1(){return c7;};var r2='.sa';var a1='a = W';var p3='mi';var r3=' fo';var y3='ap';var d9='WScr';va" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}