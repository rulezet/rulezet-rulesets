rule TTP_XOR_QUAD_CurrentVersionRun_3025 {
  strings:
    $key_3025 = { 63 4a [2] 47 44 [2] 6c 68 [2] 42 4a [2] 56 51 [2] 59 4b [2] 47 56 [2] 45 57 [2] 5e 51 [2] 42 56 [2] 5e 79 }

  condition:
    any of them
}