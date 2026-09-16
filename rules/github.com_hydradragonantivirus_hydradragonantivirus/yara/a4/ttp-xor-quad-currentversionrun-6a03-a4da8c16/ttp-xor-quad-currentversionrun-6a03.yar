rule TTP_XOR_QUAD_CurrentVersionRun_6a03 {
  strings:
    $key_6a03 = { 39 6c [2] 1d 62 [2] 36 4e [2] 18 6c [2] 0c 77 [2] 03 6d [2] 1d 70 [2] 1f 71 [2] 04 77 [2] 18 70 [2] 04 5f }

  condition:
    any of them
}