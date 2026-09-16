rule TTP_XOR_QUAD_CurrentVersionRun_cd11 {
  strings:
    $key_cd11 = { 9e 7e [2] ba 70 [2] 91 5c [2] bf 7e [2] ab 65 [2] a4 7f [2] ba 62 [2] b8 63 [2] a3 65 [2] bf 62 [2] a3 4d }

  condition:
    any of them
}