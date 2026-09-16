rule TTP_XOR_QUAD_CurrentVersionRun_6a23 {
  strings:
    $key_6a23 = { 39 4c [2] 1d 42 [2] 36 6e [2] 18 4c [2] 0c 57 [2] 03 4d [2] 1d 50 [2] 1f 51 [2] 04 57 [2] 18 50 [2] 04 7f }

  condition:
    any of them
}