rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_8b272d3350b6_4417 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"

  strings:
    $s1 = "ion fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii
    $s2 = "urn \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii
    $s3 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retu" ascii
    $s4 = "tion fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return " ascii
    $s5 = "ck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}