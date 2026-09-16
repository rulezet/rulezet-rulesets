rule TTP_XOR_QUAD_CurrentVersionRun_3734 {
  strings:
    $key_3734 = { 64 5b [2] 40 55 [2] 6b 79 [2] 45 5b [2] 51 40 [2] 5e 5a [2] 40 47 [2] 42 46 [2] 59 40 [2] 45 47 [2] 59 68 }

  condition:
    any of them
}