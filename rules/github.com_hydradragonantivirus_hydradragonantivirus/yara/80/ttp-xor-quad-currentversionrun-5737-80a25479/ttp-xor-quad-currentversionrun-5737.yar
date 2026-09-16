rule TTP_XOR_QUAD_CurrentVersionRun_5737 {
  strings:
    $key_5737 = { 04 58 [2] 20 56 [2] 0b 7a [2] 25 58 [2] 31 43 [2] 3e 59 [2] 20 44 [2] 22 45 [2] 39 43 [2] 25 44 [2] 39 6b }

  condition:
    any of them
}