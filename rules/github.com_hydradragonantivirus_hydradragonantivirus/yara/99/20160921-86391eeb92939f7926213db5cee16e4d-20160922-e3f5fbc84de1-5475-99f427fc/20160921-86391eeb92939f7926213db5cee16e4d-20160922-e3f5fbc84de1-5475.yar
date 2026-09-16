rule _20160921_86391eeb92939f7926213db5cee16e4d_20160922_e3f5fbc84de1_5475 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})" ascii
    $s2 = "eturn \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = " \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "n\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f" ascii
    $s5 = ";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}