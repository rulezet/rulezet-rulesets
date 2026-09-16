rule TTP_XOR_QUAD_CurrentVersionRun_376b {
  strings:
    $key_376b = { 64 04 [2] 40 0a [2] 6b 26 [2] 45 04 [2] 51 1f [2] 5e 05 [2] 40 18 [2] 42 19 [2] 59 1f [2] 45 18 [2] 59 37 }

  condition:
    any of them
}