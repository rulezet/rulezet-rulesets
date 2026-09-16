rule _20161125_8a52a22999e856080590515b8025dbdc_20161125_a8fb63efb971_199 {
  meta:
    description = "datamaliciousorder - from files 20161125_8a52a22999e856080590515b8025dbdc.js, 20161125_a8fb63efb9712371b3b1e8d7be501193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4f7c6863c750ee56c3d9cecc482cda53adcd6f8d425fcb5e152be59370c1d8b"
    hash2       = "29081caea958f9d27bc41dd0d31d59d7056b5a70de1f588e8a488114c6160f9d"

  strings:
    $s1  = " var TELEGRAFF500 = new Function(\"HighUpperKoreshkislickFROG2_a5,HighUpperKoreshkislickFROG2HORDA5\", 'return HighUpperKoreshki" ascii
    $s2  = "HighUpperKoreshkislickFROG2undefilled.angle = function(HighUpperKoreshkislickFROG2p) {" fullword ascii
    $s3  = "HighUpperKoreshkislickFROG2undefilled.HighUpperKoreshkislickFROG2sameOrN = function(HighUpperKoreshkislickFROG2param1, HighUpper" ascii
    $s4  = "HighUpperKoreshkislickFROG2Native.HighUpperKoreshkislickFROG2XCOPmplement = function(HighUpperKoreshkislickFROG2objects, HighUpp" ascii
    $s5  = "HighUpperKoreshkislickFROG2Native.HighUpperKoreshkislickFROG2XCOPmplement = function(HighUpperKoreshkislickFROG2objects, HighUpp" ascii
    $s6  = "HighUpperKoreshkislickFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s7  = "HighUpperKoreshkislickFROG2undefilled.HighUpperKoreshkislickFROG2sameOrN = function(HighUpperKoreshkislickFROG2param1, HighUpper" ascii
    $s8  = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickFROG2c3 == -1);" fullword ascii
    $s9  = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickRazlomSS == -1);     " ascii
    $s10 = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickRazlomSS == -1);     " ascii
    $s11 = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickFROG2c4 == -1);" fullword ascii
    $s12 = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickFROG2ddDccC2 == -1); " ascii
    $s13 = "        } while (HighUpperKoreshkislickFROG2XCOP < HighUpperKoreshkislickFROG2len && HighUpperKoreshkislickFROG2ddDccC2 == -1); " ascii
    $s14 = "HighUpperKoreshkislickoldBitch[HighUpperKoreshkislickFROG2promises ]((HighUpperKoreshkislickFROG2StrokaParam2,\"r\") +HighUpperK" ascii
    $s15 = "function  HighUpperKoreshkislickFROG2sud(vardos){" fullword ascii
    $s16 = "if (HighUpperKoreshkislickTalabaev[0]!= 77 || HighUpperKoreshkislickTalabaev[1]!= 90)return false;" fullword ascii
    $s17 = "eshkislickFROG2ddsSSddSd,0,false);" fullword ascii
    $s18 = "function  HighUpperKoreshkislickFROG2_bCho(T, D, C) {" fullword ascii
    $s19 = " var TELEGRAFF500 = new Function(\"HighUpperKoreshkislickFROG2_a5,HighUpperKoreshkislickFROG2HORDA5\", 'return HighUpperKoreshki" ascii
    $s20 = "function  HighUpperKoreshkislickFROG2_a2(HighUpperKoreshkislickFROG2gutter, HighUpperKoreshkislickFROG2StrokaParam2) {" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}