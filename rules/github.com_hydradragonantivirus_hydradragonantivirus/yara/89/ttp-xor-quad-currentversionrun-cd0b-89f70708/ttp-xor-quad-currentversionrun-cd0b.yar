rule TTP_XOR_QUAD_CurrentVersionRun_cd0b {
  strings:
    $key_cd0b = { 9e 64 [2] ba 6a [2] 91 46 [2] bf 64 [2] ab 7f [2] a4 65 [2] ba 78 [2] b8 79 [2] a3 7f [2] bf 78 [2] a3 57 }

  condition:
    any of them
}