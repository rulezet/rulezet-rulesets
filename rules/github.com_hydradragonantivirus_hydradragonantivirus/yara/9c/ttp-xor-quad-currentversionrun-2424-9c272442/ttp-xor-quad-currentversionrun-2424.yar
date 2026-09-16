rule TTP_XOR_QUAD_CurrentVersionRun_2424 {
  strings:
    $key_2424 = { 77 4b [2] 53 45 [2] 78 69 [2] 56 4b [2] 42 50 [2] 4d 4a [2] 53 57 [2] 51 56 [2] 4a 50 [2] 56 57 [2] 4a 78 }

  condition:
    any of them
}