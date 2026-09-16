rule TTP_XOR_QUAD_CurrentVersionRun_6371 {
  strings:
    $key_6371 = { 30 1e [2] 14 10 [2] 3f 3c [2] 11 1e [2] 05 05 [2] 0a 1f [2] 14 02 [2] 16 03 [2] 0d 05 [2] 11 02 [2] 0d 2d }

  condition:
    any of them
}