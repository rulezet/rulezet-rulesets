rule TTP_XOR_QUAD_CurrentVersionRun_dcf3 {
  strings:
    $key_dcf3 = { 8f 9c [2] ab 92 [2] 80 be [2] ae 9c [2] ba 87 [2] b5 9d [2] ab 80 [2] a9 81 [2] b2 87 [2] ae 80 [2] b2 af }

  condition:
    any of them
}