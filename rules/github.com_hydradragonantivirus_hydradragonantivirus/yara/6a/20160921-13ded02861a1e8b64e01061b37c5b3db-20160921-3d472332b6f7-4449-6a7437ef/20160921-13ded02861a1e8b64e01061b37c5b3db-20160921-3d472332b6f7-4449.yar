rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_3d472332b6f7_4449 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash4       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash5       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash6       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(functio" ascii
    $s2 = ")(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(" ascii
    $s3 = "rn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(f" ascii
    $s4 = "){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})()" ascii
    $s5 = ",(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}