rule TTP_XOR_QUAD_CurrentVersionRun_2b6b {
  strings:
    $key_2b6b = { 78 04 [2] 5c 0a [2] 77 26 [2] 59 04 [2] 4d 1f [2] 42 05 [2] 5c 18 [2] 5e 19 [2] 45 1f [2] 59 18 [2] 45 37 }

  condition:
    any of them
}