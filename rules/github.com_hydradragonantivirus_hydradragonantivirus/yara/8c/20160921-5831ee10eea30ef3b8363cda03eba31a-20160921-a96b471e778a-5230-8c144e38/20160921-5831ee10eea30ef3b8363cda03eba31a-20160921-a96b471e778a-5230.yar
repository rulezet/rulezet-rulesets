rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_a96b471e778a_5230 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1 = ";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s2 = "k(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ar\";}" ascii
    $s3 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MUs\";})(),(function fuck(" ascii
    $s4 = "rn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(f" ascii
    $s5 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}