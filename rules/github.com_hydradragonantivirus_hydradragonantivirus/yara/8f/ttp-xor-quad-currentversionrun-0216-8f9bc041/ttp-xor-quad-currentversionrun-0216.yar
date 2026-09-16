rule TTP_XOR_QUAD_CurrentVersionRun_0216 {
  strings:
    $key_0216 = { 51 79 [2] 75 77 [2] 5e 5b [2] 70 79 [2] 64 62 [2] 6b 78 [2] 75 65 [2] 77 64 [2] 6c 62 [2] 70 65 [2] 6c 4a }

  condition:
    any of them
}