rule TTP_XOR_QUAD_CurrentVersionRun_dcd0 {
  strings:
    $key_dcd0 = { 8f bf [2] ab b1 [2] 80 9d [2] ae bf [2] ba a4 [2] b5 be [2] ab a3 [2] a9 a2 [2] b2 a4 [2] ae a3 [2] b2 8c }

  condition:
    any of them
}