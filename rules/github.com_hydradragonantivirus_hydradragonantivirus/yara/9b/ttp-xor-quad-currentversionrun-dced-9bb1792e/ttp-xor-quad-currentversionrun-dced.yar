rule TTP_XOR_QUAD_CurrentVersionRun_dced {
  strings:
    $key_dced = { 8f 82 [2] ab 8c [2] 80 a0 [2] ae 82 [2] ba 99 [2] b5 83 [2] ab 9e [2] a9 9f [2] b2 99 [2] ae 9e [2] b2 b1 }

  condition:
    any of them
}