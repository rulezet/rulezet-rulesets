rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_073b3e31779f_1759 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash5       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash6       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash7       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash8       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash9       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash10      = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash11      = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash12      = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash13      = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1  = ";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f" ascii
    $s2  = "\"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(funct" ascii
    $s3  = "n \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(f" ascii
    $s4  = "f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe" ascii
    $s5  = "function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s6  = "ction f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s7  = "return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})()," ascii
    $s8  = "n f000(){return \"Uo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"K" ascii
    $s9  = "(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";}" ascii
    $s10 = "),(function f000(){return \"KIc\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}