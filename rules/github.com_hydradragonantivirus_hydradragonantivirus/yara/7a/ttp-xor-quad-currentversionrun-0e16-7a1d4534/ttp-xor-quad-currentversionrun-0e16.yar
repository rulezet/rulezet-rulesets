rule TTP_XOR_QUAD_CurrentVersionRun_0e16 {
  strings:
    $key_0e16 = { 5d 79 [2] 79 77 [2] 52 5b [2] 7c 79 [2] 68 62 [2] 67 78 [2] 79 65 [2] 7b 64 [2] 60 62 [2] 7c 65 [2] 60 4a }

  condition:
    any of them
}