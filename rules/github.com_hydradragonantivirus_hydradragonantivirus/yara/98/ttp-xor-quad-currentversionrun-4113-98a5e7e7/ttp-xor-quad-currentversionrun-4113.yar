rule TTP_XOR_QUAD_CurrentVersionRun_4113 {
  strings:
    $key_4113 = { 12 7c [2] 36 72 [2] 1d 5e [2] 33 7c [2] 27 67 [2] 28 7d [2] 36 60 [2] 34 61 [2] 2f 67 [2] 33 60 [2] 2f 4f }

  condition:
    any of them
}