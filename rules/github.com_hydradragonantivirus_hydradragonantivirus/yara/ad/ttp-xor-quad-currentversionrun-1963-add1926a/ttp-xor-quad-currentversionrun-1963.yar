rule TTP_XOR_QUAD_CurrentVersionRun_1963 {
  strings:
    $key_1963 = { 4a 0c [2] 6e 02 [2] 45 2e [2] 6b 0c [2] 7f 17 [2] 70 0d [2] 6e 10 [2] 6c 11 [2] 77 17 [2] 6b 10 [2] 77 3f }

  condition:
    any of them
}