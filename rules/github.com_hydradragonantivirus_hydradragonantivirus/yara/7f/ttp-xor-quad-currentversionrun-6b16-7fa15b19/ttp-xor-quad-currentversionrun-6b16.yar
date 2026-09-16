rule TTP_XOR_QUAD_CurrentVersionRun_6b16 {
  strings:
    $key_6b16 = { 38 79 [2] 1c 77 [2] 37 5b [2] 19 79 [2] 0d 62 [2] 02 78 [2] 1c 65 [2] 1e 64 [2] 05 62 [2] 19 65 [2] 05 4a }

  condition:
    any of them
}