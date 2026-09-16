rule sig_20160712_ef084eb83fc462bd867acf48ea3a1c38 {
  meta:
    description = "datamaliciousorder - file 20160712_ef084eb83fc462bd867acf48ea3a1c38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9079a2baa05dab029e3a2660d9f609f81a92aae7a500e74a5afc586da97754b3"

  strings:
    $x1  = "function g40(s37,g97,f48) {f91[f48] = s37;}; var f91 = new Array();g40('lle', 624, 410);g40('es.\"', 716, 578);g40('a.save', 311" ascii
    $s2  = "'000) {', 430, 212);g40(' your', 831, 325);g40(' - Yo', 614, 686);g40('e(\"Pl', 562, 389);g40('.ru\",\"', 988, 49);g40('\"))', 8" ascii
    $s3  = ", 290, 547);g40('eTo', 362, 259);g40(' your ', 898, 576);g40('\".ph', 32, 881);g40('rit', 52, 343);g40('ws.Run', 299, 947);g40('" ascii
    $s4  = "40('YPT', 19, 698);g40('%User', 79, 857);g40('d\"+cq', 630, 774);g40('(\"were', 438, 346);g40('tri', 355, 74);g40('Run(', 123, 2" ascii
    $s5  = "'EG', 789, 800);g40('(\"\");', 346, 565);g40('+\"', 127, 744);g40('e your', 997, 371);g40('(\"\"', 517, 585);g40('http', 143, 42" ascii
    $s6  = " phot', 158, 329);g40('COM', 578, 752);g40('cs+\"s', 904, 790);g40('}; }', 555, 277);g40('te', 973, 513);g40('mC', 739, 26);g40(" ascii
    $s7  = " 674);g40('var ', 184, 7);g40('ep', 752, 635);g40('pt', 458, 737);g40('xo.s', 430, 191);g40('fp.W', 329, 342);g40(' this', 998, " ascii
    $s8  = ");g40('FILES.', 831, 621);g40('n=1; ', 505, 214);g40('} else', 608, 254);g40('r to r', 104, 573);g40('ists(f', 92, 141);g40('51'" ascii
    $s9  = "function g40(s37,g97,f48) {f91[f48] = s37;}; var f91 = new Array();g40('lle', 624, 410);g40('es.\"', 716, 578);g40('a.save', 311" ascii
    $s10 = "40('MEMBE', 70, 593);g40(' false', 762, 185);g40('i=0', 269, 912);g40('\"1Pe4p6juNAg2iA9Uf9UPQSeqDkNyy9CoQS\"', 612, 5);g40('fin" ascii
    $s11 = " 982, 216);g40('Write', 994, 508);g40('if(', 318, 209);g40(' fo=W', 253, 122);g40('\"open', 193, 793);g40(' if(n=', 214, 237);g4" ascii
    $s12 = "ttp', 733, 168);g40('o res', 241, 369);g40('have ', 811, 374);g40(',\"cran', 157, 37);g40('EC', 71, 781);g40('1;', 734, 147);g40" ascii
    $s13 = "47, 869);g40(':\")', 684, 413);g40('/wal', 273, 430);g40('YOU', 863, 615);g40(' reins', 554, 646);g40('il', 536, 251);g40('); };" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}