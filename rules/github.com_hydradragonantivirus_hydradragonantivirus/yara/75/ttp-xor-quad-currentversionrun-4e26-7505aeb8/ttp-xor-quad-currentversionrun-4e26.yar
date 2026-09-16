rule TTP_XOR_QUAD_CurrentVersionRun_4e26 {
  strings:
    $key_4e26 = { 1d 49 [2] 39 47 [2] 12 6b [2] 3c 49 [2] 28 52 [2] 27 48 [2] 39 55 [2] 3b 54 [2] 20 52 [2] 3c 55 [2] 20 7a }

  condition:
    any of them
}