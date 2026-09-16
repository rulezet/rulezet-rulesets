rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_232b12ddd1b9_4214 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash3       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash4       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash5       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash6       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash7       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"
    hash8       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1 = "urn \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s2 = "a\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function" ascii
    $s3 = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s4 = "{return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";}" ascii
    $s5 = "uck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}