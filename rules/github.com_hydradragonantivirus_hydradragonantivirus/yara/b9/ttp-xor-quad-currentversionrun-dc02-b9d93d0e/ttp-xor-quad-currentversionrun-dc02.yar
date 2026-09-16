rule TTP_XOR_QUAD_CurrentVersionRun_dc02 {
  strings:
    $key_dc02 = { 8f 6d [2] ab 63 [2] 80 4f [2] ae 6d [2] ba 76 [2] b5 6c [2] ab 71 [2] a9 70 [2] b2 76 [2] ae 71 [2] b2 5e }

  condition:
    any of them
}