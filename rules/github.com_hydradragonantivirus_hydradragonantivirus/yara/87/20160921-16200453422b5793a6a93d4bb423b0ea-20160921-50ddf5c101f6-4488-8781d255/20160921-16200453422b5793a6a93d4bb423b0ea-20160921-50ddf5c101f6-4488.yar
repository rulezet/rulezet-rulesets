rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_50ddf5c101f6_4488 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash3       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash4       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){retu" ascii
    $s2 = "\"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(func" ascii
    $s3 = "nction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){retur" ascii
    $s4 = "on f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s5 = "return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}