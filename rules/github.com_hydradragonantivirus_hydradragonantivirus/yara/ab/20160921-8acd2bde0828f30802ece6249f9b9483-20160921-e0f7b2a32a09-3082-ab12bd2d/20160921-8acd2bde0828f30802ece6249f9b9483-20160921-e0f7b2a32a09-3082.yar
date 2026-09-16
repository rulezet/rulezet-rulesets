rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_e0f7b2a32a09_3082 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "urn \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";}" ascii
    $s3 = ",(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s4 = "Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s5 = "\"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(func" ascii
    $s6 = "ion fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s7 = "k(){return \"Ot\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"RAi\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}