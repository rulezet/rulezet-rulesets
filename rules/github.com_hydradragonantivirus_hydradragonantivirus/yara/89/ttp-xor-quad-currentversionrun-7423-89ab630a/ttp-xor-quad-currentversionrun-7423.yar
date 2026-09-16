rule TTP_XOR_QUAD_CurrentVersionRun_7423 {
  strings:
    $key_7423 = { 27 4c [2] 03 42 [2] 28 6e [2] 06 4c [2] 12 57 [2] 1d 4d [2] 03 50 [2] 01 51 [2] 1a 57 [2] 06 50 [2] 1a 7f }

  condition:
    any of them
}