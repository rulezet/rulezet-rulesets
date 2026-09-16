rule TTP_XOR_QUAD_CurrentVersionRun_cd88 {
  strings:
    $key_cd88 = { 9e e7 [2] ba e9 [2] 91 c5 [2] bf e7 [2] ab fc [2] a4 e6 [2] ba fb [2] b8 fa [2] a3 fc [2] bf fb [2] a3 d4 }

  condition:
    any of them
}