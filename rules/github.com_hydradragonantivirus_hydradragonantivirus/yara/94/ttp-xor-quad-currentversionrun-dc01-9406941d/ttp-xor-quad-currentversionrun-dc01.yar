rule TTP_XOR_QUAD_CurrentVersionRun_dc01 {
  strings:
    $key_dc01 = { 8f 6e [2] ab 60 [2] 80 4c [2] ae 6e [2] ba 75 [2] b5 6f [2] ab 72 [2] a9 73 [2] b2 75 [2] ae 72 [2] b2 5d }

  condition:
    any of them
}