rule TTP_XOR_QUAD_CurrentVersionRun_cd31 {
  strings:
    $key_cd31 = { 9e 5e [2] ba 50 [2] 91 7c [2] bf 5e [2] ab 45 [2] a4 5f [2] ba 42 [2] b8 43 [2] a3 45 [2] bf 42 [2] a3 6d }

  condition:
    any of them
}