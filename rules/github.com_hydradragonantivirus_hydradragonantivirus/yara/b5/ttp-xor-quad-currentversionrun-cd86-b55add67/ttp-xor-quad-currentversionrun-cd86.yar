rule TTP_XOR_QUAD_CurrentVersionRun_cd86 {
  strings:
    $key_cd86 = { 9e e9 [2] ba e7 [2] 91 cb [2] bf e9 [2] ab f2 [2] a4 e8 [2] ba f5 [2] b8 f4 [2] a3 f2 [2] bf f5 [2] a3 da }

  condition:
    any of them
}