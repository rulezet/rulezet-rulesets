rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_e07d4e2b8017_3970 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "k(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\"" ascii
    $s2 = " \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Yk\";})(),(func" ascii
    $s3 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){" ascii
    $s4 = "\"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(fun" ascii
    $s5 = "\"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(fun" ascii
    $s6 = "unction fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}