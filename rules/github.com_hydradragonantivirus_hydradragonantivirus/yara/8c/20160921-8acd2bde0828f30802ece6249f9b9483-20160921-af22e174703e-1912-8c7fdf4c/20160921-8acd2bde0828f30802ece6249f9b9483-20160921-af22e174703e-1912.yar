rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_af22e174703e_1912 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1  = "{return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";}" ascii
    $s2  = "rn \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s3  = "x\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s4  = "n fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s5  = "})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(" ascii
    $s6  = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retur" ascii
    $s7  = "){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})" ascii
    $s8  = "function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s9  = "turn \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})()," ascii
    $s10 = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}