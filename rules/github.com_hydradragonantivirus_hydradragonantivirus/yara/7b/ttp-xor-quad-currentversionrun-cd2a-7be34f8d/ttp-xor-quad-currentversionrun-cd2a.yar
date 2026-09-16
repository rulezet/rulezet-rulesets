rule TTP_XOR_QUAD_CurrentVersionRun_cd2a {
  strings:
    $key_cd2a = { 9e 45 [2] ba 4b [2] 91 67 [2] bf 45 [2] ab 5e [2] a4 44 [2] ba 59 [2] b8 58 [2] a3 5e [2] bf 59 [2] a3 76 }

  condition:
    any of them
}