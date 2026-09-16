rule TTP_XOR_QUAD_CurrentVersionRun_3e26 {
  strings:
    $key_3e26 = { 6d 49 [2] 49 47 [2] 62 6b [2] 4c 49 [2] 58 52 [2] 57 48 [2] 49 55 [2] 4b 54 [2] 50 52 [2] 4c 55 [2] 50 7a }

  condition:
    any of them
}