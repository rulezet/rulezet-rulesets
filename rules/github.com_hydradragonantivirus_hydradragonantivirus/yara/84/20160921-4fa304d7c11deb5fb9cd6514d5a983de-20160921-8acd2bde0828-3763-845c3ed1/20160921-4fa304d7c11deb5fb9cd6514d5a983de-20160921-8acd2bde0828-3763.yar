rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_8acd2bde0828_3763 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"

  strings:
    $s1 = "rn \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s2 = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck" ascii
    $s3 = " fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"KV" ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s5 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function f" ascii
    $s6 = "k(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}