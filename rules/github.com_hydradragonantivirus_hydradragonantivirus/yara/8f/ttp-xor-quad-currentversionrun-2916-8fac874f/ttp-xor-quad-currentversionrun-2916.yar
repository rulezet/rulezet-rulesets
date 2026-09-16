rule TTP_XOR_QUAD_CurrentVersionRun_2916 {
  strings:
    $key_2916 = { 7a 79 [2] 5e 77 [2] 75 5b [2] 5b 79 [2] 4f 62 [2] 40 78 [2] 5e 65 [2] 5c 64 [2] 47 62 [2] 5b 65 [2] 47 4a }

  condition:
    any of them
}