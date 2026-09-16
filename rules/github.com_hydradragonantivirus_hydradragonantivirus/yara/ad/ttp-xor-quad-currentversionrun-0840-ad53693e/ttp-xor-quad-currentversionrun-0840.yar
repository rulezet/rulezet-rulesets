rule TTP_XOR_QUAD_CurrentVersionRun_0840 {
  strings:
    $key_0840 = { 5b 2f [2] 7f 21 [2] 54 0d [2] 7a 2f [2] 6e 34 [2] 61 2e [2] 7f 33 [2] 7d 32 [2] 66 34 [2] 7a 33 [2] 66 1c }

  condition:
    any of them
}