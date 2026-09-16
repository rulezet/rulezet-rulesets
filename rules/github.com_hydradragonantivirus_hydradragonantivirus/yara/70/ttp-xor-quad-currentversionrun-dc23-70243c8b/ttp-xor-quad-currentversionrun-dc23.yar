rule TTP_XOR_QUAD_CurrentVersionRun_dc23 {
  strings:
    $key_dc23 = { 8f 4c [2] ab 42 [2] 80 6e [2] ae 4c [2] ba 57 [2] b5 4d [2] ab 50 [2] a9 51 [2] b2 57 [2] ae 50 [2] b2 7f }

  condition:
    any of them
}