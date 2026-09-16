rule _20160921_50ddf5c101f65dbae1a99b5967b69eaf_20160921_7912bf379029_5162 {
  meta:
    description = "datamaliciousorder - from files 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash2       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2 = "(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s3 = "000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx" ascii
    $s4 = "nction f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s5 = "00(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}