rule TTP_XOR_QUAD_CurrentVersionRun_cd16 {
  strings:
    $key_cd16 = { 9e 79 [2] ba 77 [2] 91 5b [2] bf 79 [2] ab 62 [2] a4 78 [2] ba 65 [2] b8 64 [2] a3 62 [2] bf 65 [2] a3 4a }

  condition:
    any of them
}