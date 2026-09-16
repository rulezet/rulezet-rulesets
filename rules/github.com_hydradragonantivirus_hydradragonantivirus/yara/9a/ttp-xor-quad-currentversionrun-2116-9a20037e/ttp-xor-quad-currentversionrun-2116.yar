rule TTP_XOR_QUAD_CurrentVersionRun_2116 {
  strings:
    $key_2116 = { 72 79 [2] 56 77 [2] 7d 5b [2] 53 79 [2] 47 62 [2] 48 78 [2] 56 65 [2] 54 64 [2] 4f 62 [2] 53 65 [2] 4f 4a }

  condition:
    any of them
}