rule TTP_XOR_QUAD_CurrentVersionRun_dc31 {
  strings:
    $key_dc31 = { 8f 5e [2] ab 50 [2] 80 7c [2] ae 5e [2] ba 45 [2] b5 5f [2] ab 42 [2] a9 43 [2] b2 45 [2] ae 42 [2] b2 6d }

  condition:
    any of them
}