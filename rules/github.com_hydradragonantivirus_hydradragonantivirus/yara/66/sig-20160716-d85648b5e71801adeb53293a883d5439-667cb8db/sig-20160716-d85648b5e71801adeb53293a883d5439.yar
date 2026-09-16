rule sig_20160716_d85648b5e71801adeb53293a883d5439 {
  meta:
    description = "datamaliciousorder - file 20160716_d85648b5e71801adeb53293a883d5439.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce6994210a98b12700a6fdbc974706e9a6cee8b5802b495dd926a406986b70bd"

  strings:
    $x1  = "function h83(n16,f11,i67) {x77[i67] = n16;}; var x77 = new Array();h83('th', 26, 429);h83('in\"', 570, 52);h83('.vn\"', 439, 44)" ascii
    $s2  = "20);h83('SE', 330, 569);h83('r y', 232, 651);h83('ros', 144, 697);h83('e anti', 279, 630);h83('ws.Run', 993, 920);h83('r bc=\"'," ascii
    $s3  = "ypt', 100, 647);h83('00) { ', 622, 184);h83('or(v', 906, 144);h83('sts(pd', 866, 275);h83(' /F', 228, 782);h83('r file', 81, 557" ascii
    $s4  = "('- Y', 224, 641);h83(' LOOSE', 104, 589);h83('.clos', 931, 253);h83('c copy', 957, 834);h83('\"); ', 359, 351);h83('de', 936, 1" ascii
    $s5  = ");h83('ine(', 935, 444);h83('\"+', 829, 725);h83('files\"', 65, 329);h83(' here', 806, 395);h83('un(fn', 339, 212);h83('to thi'," ascii
    $s6  = "function h83(n16,f11,i67) {x77[i67] = n16;}; var x77 = new Array();h83('th', 26, 429);h83('in\"', 570, 52);h83('.vn\"', 439, 44)" ascii
    $s7  = "', 905, 305);h83('\"PLEA', 491, 568);h83(';} ', 143, 220);h83('\")) { ', 32, 137);h83('Wr', 361, 547);h83('RE\"+cs', 417, 695);h" ascii
    $s8  = "97, 577);h83(' days ', 493, 587);h83('iteLin', 420, 903);h83('& fo.', 945, 277);h83('ri', 888, 57);h83('Char', 268, 23);h83('o '" ascii
    $s9  = ");h83('; var ', 893, 11);h83('c ', 522, 759);h83('ToFil', 516, 237);h83('sktop', 741, 820);h83('t(\"WS', 573, 62);h83('\"DECRY'," ascii
    $s10 = "2, 686);h83('ns', 509, 450);h83('xe\",2)', 571, 229);h83(' Open', 738, 495);h83('dn=0; ', 729, 153);h83('OMSPE', 838, 757);h83('" ascii
    $s11 = ", 724);h83('=\"+', 52, 172);h83('cq,0,', 848, 726);h83('less', 377, 620);h83('p.', 240, 906);h83(' cash,', 659, 430);h83('\"+cq," ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and all of them
}