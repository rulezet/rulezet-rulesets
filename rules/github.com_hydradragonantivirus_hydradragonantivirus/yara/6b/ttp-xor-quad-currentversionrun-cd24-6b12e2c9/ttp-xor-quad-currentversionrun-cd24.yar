rule TTP_XOR_QUAD_CurrentVersionRun_cd24 {
  strings:
    $key_cd24 = { 9e 4b [2] ba 45 [2] 91 69 [2] bf 4b [2] ab 50 [2] a4 4a [2] ba 57 [2] b8 56 [2] a3 50 [2] bf 57 [2] a3 78 }

  condition:
    any of them
}