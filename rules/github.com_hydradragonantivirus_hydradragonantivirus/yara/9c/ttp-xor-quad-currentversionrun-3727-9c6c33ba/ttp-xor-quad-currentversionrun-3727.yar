rule TTP_XOR_QUAD_CurrentVersionRun_3727 {
  strings:
    $key_3727 = { 64 48 [2] 40 46 [2] 6b 6a [2] 45 48 [2] 51 53 [2] 5e 49 [2] 40 54 [2] 42 55 [2] 59 53 [2] 45 54 [2] 59 7b }

  condition:
    any of them
}