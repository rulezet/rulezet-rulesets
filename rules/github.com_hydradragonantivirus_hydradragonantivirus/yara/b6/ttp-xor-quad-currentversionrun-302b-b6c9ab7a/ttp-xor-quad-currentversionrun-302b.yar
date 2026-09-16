rule TTP_XOR_QUAD_CurrentVersionRun_302b {
  strings:
    $key_302b = { 63 44 [2] 47 4a [2] 6c 66 [2] 42 44 [2] 56 5f [2] 59 45 [2] 47 58 [2] 45 59 [2] 5e 5f [2] 42 58 [2] 5e 77 }

  condition:
    any of them
}