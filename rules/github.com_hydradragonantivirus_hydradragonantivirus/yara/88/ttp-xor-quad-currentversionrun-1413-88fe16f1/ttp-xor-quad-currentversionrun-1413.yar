rule TTP_XOR_QUAD_CurrentVersionRun_1413 {
  strings:
    $key_1413 = { 47 7c [2] 63 72 [2] 48 5e [2] 66 7c [2] 72 67 [2] 7d 7d [2] 63 60 [2] 61 61 [2] 7a 67 [2] 66 60 [2] 7a 4f }

  condition:
    any of them
}