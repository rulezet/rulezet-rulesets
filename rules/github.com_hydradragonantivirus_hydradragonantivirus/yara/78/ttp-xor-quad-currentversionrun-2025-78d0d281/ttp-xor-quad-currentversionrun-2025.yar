rule TTP_XOR_QUAD_CurrentVersionRun_2025 {
  strings:
    $key_2025 = { 73 4a [2] 57 44 [2] 7c 68 [2] 52 4a [2] 46 51 [2] 49 4b [2] 57 56 [2] 55 57 [2] 4e 51 [2] 52 56 [2] 4e 79 }

  condition:
    any of them
}