rule TTP_XOR_QUAD_CurrentVersionRun_cd3b {
  strings:
    $key_cd3b = { 9e 54 [2] ba 5a [2] 91 76 [2] bf 54 [2] ab 4f [2] a4 55 [2] ba 48 [2] b8 49 [2] a3 4f [2] bf 48 [2] a3 67 }

  condition:
    any of them
}