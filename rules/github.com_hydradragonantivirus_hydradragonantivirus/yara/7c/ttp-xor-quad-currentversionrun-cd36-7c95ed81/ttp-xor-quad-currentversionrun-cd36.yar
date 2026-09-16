rule TTP_XOR_QUAD_CurrentVersionRun_cd36 {
  strings:
    $key_cd36 = { 9e 59 [2] ba 57 [2] 91 7b [2] bf 59 [2] ab 42 [2] a4 58 [2] ba 45 [2] b8 44 [2] a3 42 [2] bf 45 [2] a3 6a }

  condition:
    any of them
}