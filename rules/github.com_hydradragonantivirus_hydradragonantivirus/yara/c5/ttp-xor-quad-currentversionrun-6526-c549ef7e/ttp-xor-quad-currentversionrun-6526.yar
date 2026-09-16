rule TTP_XOR_QUAD_CurrentVersionRun_6526 {
  strings:
    $key_6526 = { 36 49 [2] 12 47 [2] 39 6b [2] 17 49 [2] 03 52 [2] 0c 48 [2] 12 55 [2] 10 54 [2] 0b 52 [2] 17 55 [2] 0b 7a }

  condition:
    any of them
}