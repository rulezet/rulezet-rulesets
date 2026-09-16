rule TTP_XOR_QUAD_CurrentVersionRun_0b26 {
  strings:
    $key_0b26 = { 58 49 [2] 7c 47 [2] 57 6b [2] 79 49 [2] 6d 52 [2] 62 48 [2] 7c 55 [2] 7e 54 [2] 65 52 [2] 79 55 [2] 65 7a }

  condition:
    any of them
}