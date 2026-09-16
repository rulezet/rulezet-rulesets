rule TTP_XOR_QUAD_CurrentVersionRun_cd07 {
  strings:
    $key_cd07 = { 9e 68 [2] ba 66 [2] 91 4a [2] bf 68 [2] ab 73 [2] a4 69 [2] ba 74 [2] b8 75 [2] a3 73 [2] bf 74 [2] a3 5b }

  condition:
    any of them
}