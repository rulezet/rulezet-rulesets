rule TTP_XOR_QUAD_CurrentVersionRun_6513 {
  strings:
    $key_6513 = { 36 7c [2] 12 72 [2] 39 5e [2] 17 7c [2] 03 67 [2] 0c 7d [2] 12 60 [2] 10 61 [2] 0b 67 [2] 17 60 [2] 0b 4f }

  condition:
    any of them
}