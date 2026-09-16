rule TTP_XOR_QUAD_CurrentVersionRun_5763 {
  strings:
    $key_5763 = { 04 0c [2] 20 02 [2] 0b 2e [2] 25 0c [2] 31 17 [2] 3e 0d [2] 20 10 [2] 22 11 [2] 39 17 [2] 25 10 [2] 39 3f }

  condition:
    any of them
}