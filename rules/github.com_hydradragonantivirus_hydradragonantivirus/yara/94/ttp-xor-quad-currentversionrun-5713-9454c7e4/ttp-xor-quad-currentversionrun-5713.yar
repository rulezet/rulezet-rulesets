rule TTP_XOR_QUAD_CurrentVersionRun_5713 {
  strings:
    $key_5713 = { 04 7c [2] 20 72 [2] 0b 5e [2] 25 7c [2] 31 67 [2] 3e 7d [2] 20 60 [2] 22 61 [2] 39 67 [2] 25 60 [2] 39 4f }

  condition:
    any of them
}