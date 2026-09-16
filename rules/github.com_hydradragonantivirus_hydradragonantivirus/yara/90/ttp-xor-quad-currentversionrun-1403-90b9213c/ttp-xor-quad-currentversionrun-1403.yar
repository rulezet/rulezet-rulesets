rule TTP_XOR_QUAD_CurrentVersionRun_1403 {
  strings:
    $key_1403 = { 47 6c [2] 63 62 [2] 48 4e [2] 66 6c [2] 72 77 [2] 7d 6d [2] 63 70 [2] 61 71 [2] 7a 77 [2] 66 70 [2] 7a 5f }

  condition:
    any of them
}