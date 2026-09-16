rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_17bab7cc945f_4452 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash3       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash4       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash5       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash6       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"
    hash7       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "tion f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s2 = "(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){re" ascii
    $s3 = "Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})()" ascii
    $s5 = "{return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}