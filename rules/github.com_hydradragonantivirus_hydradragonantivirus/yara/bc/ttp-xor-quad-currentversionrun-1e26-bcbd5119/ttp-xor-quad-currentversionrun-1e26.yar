rule TTP_XOR_QUAD_CurrentVersionRun_1e26 {
  strings:
    $key_1e26 = { 4d 49 [2] 69 47 [2] 42 6b [2] 6c 49 [2] 78 52 [2] 77 48 [2] 69 55 [2] 6b 54 [2] 70 52 [2] 6c 55 [2] 70 7a }

  condition:
    any of them
}