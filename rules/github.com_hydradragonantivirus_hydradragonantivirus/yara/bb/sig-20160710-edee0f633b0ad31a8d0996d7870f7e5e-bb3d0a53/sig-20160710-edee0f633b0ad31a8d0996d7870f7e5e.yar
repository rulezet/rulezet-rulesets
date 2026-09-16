rule sig_20160710_edee0f633b0ad31a8d0996d7870f7e5e {
  meta:
    description = "datamaliciousorder - file 20160710_edee0f633b0ad31a8d0996d7870f7e5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f754fbce5bf9e9ab7cd2326fd6ebae874c314d5622088e947666b81f6546998"

  strings:
    $x1  = "function d33(o62,u45) {u85[o62] = u45;}; var u85 = new Array();d33(816, '+cq+');d33(744, 'Run(\"');d33(938, 'q,0,0)');d33(681, '" ascii
    $s2  = ";d33(753, '+\".cry');d33(758, 've /t');d33(233, 'a.sav');d33(720, 'rsion\"');d33(366, 'ne(\"T');d33(850, '%User');d33(85, 'viro'" ascii
    $s3  = ", '\"%TEMP');d33(231, '=3)');d33(276, '; };');d33(200, 'y)');d33(216, 'ws.Ru');d33(65, ');');d33(405, 'oin w');d33(948, ',0,0)')" ascii
    $s4  = ";d33(73, 'St');d33(791, 've /t');d33(492, 'Lin');d33(903, ');for');d33(928, 'un(\"');d33(367, 'o rest');d33(611, 'e(');d33(426, " ascii
    $s5  = "function d33(o62,u45) {u85[o62] = u45;}; var u85 = new Array();d33(816, '+cq+');d33(744, 'Run(\"');d33(938, 'q,0,0)');d33(681, '" ascii
    $s6  = "');d33(902, ',true');d33(14, 'var ');d33(326, ' you');d33(543, '\" ');d33(743, '; ws.');d33(595, '    - ');d33(199, 'od');d33(25" ascii
    $s7  = "7, '); fp.');d33(711, 'RE\"+c');d33(101, 'ate');d33(370, ' file');d33(705, '\"+cq');d33(310, 'ne');d33(116, '\"ADO');d33(106, 'X" ascii
    $s8  = "W');d33(788, '+c');d33(270, '; }');d33(606, 'R FILE');d33(398, '\"\"');d33(925, 'cq,0,0');d33(27, 'ode');d33(283, '&&');d33(526," ascii
    $s9  = "');d33(403, ' Creat');d33(939, '; ');d33(126, 'eObjec');d33(451, ');');d33(749, 'DD \"');d33(450, 'ne(\"\"');d33(96, 'xo=');d33(" ascii
    $s10 = "(923, 'n+\".ph');d33(755, 'd\"');d33(718, '+\"Curr');d33(666, 'te');d33(98, 'ip');d33(289, ' f');d33(411, 'WriteL');d33(125, '.C" ascii
    $s11 = "33(636, 'tall');d33(830, 's+\"D');d33(759, ' REG_');d33(183, '(xo');d33(169, 'nter');d33(275, ' }');d33(439, ' with');d33(586, '" ascii
    $s12 = "'n+\".');d33(35, 'mt');d33(646, 's soft');d33(800, '.ex');d33(373, ' t');d33(825, 'Data%\"');d33(241, 'f(n==');d33(388, 'e foll'" ascii
    $s13 = "this');d33(932, 'c DEL');d33(638, 'in');d33(886, ' \"');d33(892, ' var f');d33(400, '.Write');d33(190, 'en();');d33(60, 'bjec');" ascii
    $s14 = "d33(936, 'ex');d33(224, '}cat');d33(115, 'ct(');d33(92, '\"php4t');d33(534, '0;i<l');d33(517, ' your ');d33(893, 'p=');d33(554, " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}