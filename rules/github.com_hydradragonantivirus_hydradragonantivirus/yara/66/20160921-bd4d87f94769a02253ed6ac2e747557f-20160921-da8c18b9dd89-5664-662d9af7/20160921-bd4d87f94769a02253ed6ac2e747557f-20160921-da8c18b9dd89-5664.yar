rule _20160921_bd4d87f94769a02253ed6ac2e747557f_20160921_da8c18b9dd89_5664 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash2       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1 = "urn \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(f" ascii
    $s2 = "c\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function " ascii
    $s3 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s4 = "function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retu" ascii
    $s5 = "rn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}