rule TTP_XOR_QUAD_CurrentVersionRun_7013 {
  strings:
    $key_7013 = { 23 7c [2] 07 72 [2] 2c 5e [2] 02 7c [2] 16 67 [2] 19 7d [2] 07 60 [2] 05 61 [2] 1e 67 [2] 02 60 [2] 1e 4f }

  condition:
    any of them
}