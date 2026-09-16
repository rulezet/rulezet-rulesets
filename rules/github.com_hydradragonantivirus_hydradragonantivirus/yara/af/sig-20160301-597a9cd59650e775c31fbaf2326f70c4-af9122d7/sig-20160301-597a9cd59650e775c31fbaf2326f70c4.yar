rule sig_20160301_597a9cd59650e775c31fbaf2326f70c4 {
  meta:
    description = "datamaliciousorder - file 20160301_597a9cd59650e775c31fbaf2326f70c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a43b13417bc73dd693661c721640f204912647ce270f33aa484de10c737000d4"

  strings:
    $s1 = "boxRegion = lordPassive[(\"\\u0070\\u006fs\" + \"\\u0069ti\" + \"on\", \"in\" + \"e\\u0072\\u0074\", \"t\\u0072a\\u006e\\u0073i" ascii
    $s2 = "0063\\u0068\", \"m\\u0061\\u0073t\" + \"\\u0065r\", function String.prototype.basisRecommend() {" fullword ascii
    $s3 = "while(cipherFocus[(\"pr\\u0065c\\u0065\\u0064\" + \"e\\u006et\", \"t\\u0065m\\u0070e\" + \"\\u0072a\\u0074ur\\u0065\", \"p\\u006" ascii
    $s4 = "specialMoral = (((([+[]])) ^ (148, 3, 1)), this);" fullword ascii
    $s5 = "while(cipherFocus[(\"pr\\u0065c\\u0065\\u0064\" + \"e\\u006et\", \"t\\u0065m\\u0070e\" + \"\\u0072a\\u0074ur\\u0065\", \"p\\u006" ascii
    $s6 = "} catch(metaphorPlan) {};" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    all of them
}