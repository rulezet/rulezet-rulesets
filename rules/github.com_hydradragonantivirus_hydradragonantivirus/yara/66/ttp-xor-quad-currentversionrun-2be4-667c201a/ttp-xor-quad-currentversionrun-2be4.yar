rule TTP_XOR_QUAD_CurrentVersionRun_2be4 {
  strings:
    $key_2be4 = { 78 8b [2] 5c 85 [2] 77 a9 [2] 59 8b [2] 4d 90 [2] 42 8a [2] 5c 97 [2] 5e 96 [2] 45 90 [2] 59 97 [2] 45 b8 }

  condition:
    any of them
}