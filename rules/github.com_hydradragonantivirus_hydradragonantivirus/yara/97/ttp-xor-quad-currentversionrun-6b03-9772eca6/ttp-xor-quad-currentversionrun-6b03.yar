rule TTP_XOR_QUAD_CurrentVersionRun_6b03 {
  strings:
    $key_6b03 = { 38 6c [2] 1c 62 [2] 37 4e [2] 19 6c [2] 0d 77 [2] 02 6d [2] 1c 70 [2] 1e 71 [2] 05 77 [2] 19 70 [2] 05 5f }

  condition:
    any of them
}