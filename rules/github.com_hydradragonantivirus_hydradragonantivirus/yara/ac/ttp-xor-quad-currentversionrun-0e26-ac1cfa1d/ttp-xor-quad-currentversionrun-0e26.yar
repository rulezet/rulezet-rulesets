rule TTP_XOR_QUAD_CurrentVersionRun_0e26 {
  strings:
    $key_0e26 = { 5d 49 [2] 79 47 [2] 52 6b [2] 7c 49 [2] 68 52 [2] 67 48 [2] 79 55 [2] 7b 54 [2] 60 52 [2] 7c 55 [2] 60 7a }

  condition:
    any of them
}