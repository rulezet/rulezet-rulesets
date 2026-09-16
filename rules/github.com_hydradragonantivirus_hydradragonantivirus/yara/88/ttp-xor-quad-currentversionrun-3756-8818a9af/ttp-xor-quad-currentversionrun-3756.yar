rule TTP_XOR_QUAD_CurrentVersionRun_3756 {
  strings:
    $key_3756 = { 64 39 [2] 40 37 [2] 6b 1b [2] 45 39 [2] 51 22 [2] 5e 38 [2] 40 25 [2] 42 24 [2] 59 22 [2] 45 25 [2] 59 0a }

  condition:
    any of them
}