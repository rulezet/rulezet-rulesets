rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_35e8549205da_467 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash3       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash4       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash5       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash6       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash7       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash8       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash9       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Um\";})(),(func" ascii
    $s2  = "Eg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s3  = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})()" ascii
    $s4  = "rn \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5  = "rn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(f" ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"NYh\";})(),(func" ascii
    $s7  = "(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){r" ascii
    $s8  = "f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"DYx" ascii
    $s9  = ";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s10 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\"" ascii
    $s11 = "00(){return \"Sv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s12 = "(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s13 = "r\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function " ascii
    $s14 = "turn \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s15 = "0(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s16 = "\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function " ascii
    $s17 = "return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})()" ascii
    $s18 = "turn \"Mc\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s19 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"" ascii
    $s20 = "function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}