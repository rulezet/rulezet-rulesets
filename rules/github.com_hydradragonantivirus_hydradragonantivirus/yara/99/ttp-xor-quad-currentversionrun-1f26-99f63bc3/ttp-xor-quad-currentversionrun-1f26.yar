rule TTP_XOR_QUAD_CurrentVersionRun_1f26 {
  strings:
    $key_1f26 = { 4c 49 [2] 68 47 [2] 43 6b [2] 6d 49 [2] 79 52 [2] 76 48 [2] 68 55 [2] 6a 54 [2] 71 52 [2] 6d 55 [2] 71 7a }

  condition:
    any of them
}