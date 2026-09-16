rule sig_20160301_b61c83539bf619b8e1158dfdda31bb7f {
  meta:
    description = "datamaliciousorder - file 20160301_b61c83539bf619b8e1158dfdda31bb7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cbfbe84755368a4d787c6095ecce96efa70e9874263b7a8d134e357952735e"

  strings:
    $s1 = "while(internationalModify[(\"\\u0072e\\u0066l\" + \"ex\", \"exp\" + \"er\\u0074\", \"\\u0073e\" + \"rv\" + \"\\u0069\\u0063e\", " ascii
    $s2 = "internationalModify[(\"a\\u0072\\u0063a\" + \"\\u0064e\", function String.prototype.amputateTransportation() {" fullword ascii
    $s3 = "while(internationalModify[(\"\\u0072e\\u0066l\" + \"ex\", \"exp\" + \"er\\u0074\", \"\\u0073e\" + \"rv\" + \"\\u0069\\u0063e\", " ascii
    $s4 = "} catch(passPhenomenon) {};" fullword ascii
    $s5 = "vacantZombie = ((([+!+[]])), this);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}