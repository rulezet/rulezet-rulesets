rule TTP_XOR_QUAD_CurrentVersionRun_7213 {
  strings:
    $key_7213 = { 21 7c [2] 05 72 [2] 2e 5e [2] 00 7c [2] 14 67 [2] 1b 7d [2] 05 60 [2] 07 61 [2] 1c 67 [2] 00 60 [2] 1c 4f }

  condition:
    any of them
}