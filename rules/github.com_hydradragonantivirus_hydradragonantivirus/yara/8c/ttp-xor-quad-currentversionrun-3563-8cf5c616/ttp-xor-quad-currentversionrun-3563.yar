rule TTP_XOR_QUAD_CurrentVersionRun_3563 {
  strings:
    $key_3563 = { 66 0c [2] 42 02 [2] 69 2e [2] 47 0c [2] 53 17 [2] 5c 0d [2] 42 10 [2] 40 11 [2] 5b 17 [2] 47 10 [2] 5b 3f }

  condition:
    any of them
}