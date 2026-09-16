rule TTP_XOR_QUAD_CurrentVersionRun_7963 {
  strings:
    $key_7963 = { 2a 0c [2] 0e 02 [2] 25 2e [2] 0b 0c [2] 1f 17 [2] 10 0d [2] 0e 10 [2] 0c 11 [2] 17 17 [2] 0b 10 [2] 17 3f }

  condition:
    any of them
}