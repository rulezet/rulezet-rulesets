rule TTP_XOR_QUAD_CurrentVersionRun_cde0 {
  strings:
    $key_cde0 = { 9e 8f [2] ba 81 [2] 91 ad [2] bf 8f [2] ab 94 [2] a4 8e [2] ba 93 [2] b8 92 [2] a3 94 [2] bf 93 [2] a3 bc }

  condition:
    any of them
}