rule TTP_XOR_QUAD_CurrentVersionRun_376a {
  strings:
    $key_376a = { 64 05 [2] 40 0b [2] 6b 27 [2] 45 05 [2] 51 1e [2] 5e 04 [2] 40 19 [2] 42 18 [2] 59 1e [2] 45 19 [2] 59 36 }

  condition:
    any of them
}