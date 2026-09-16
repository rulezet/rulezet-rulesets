rule TTP_XOR_QUAD_CurrentVersionRun_5754 {
  strings:
    $key_5754 = { 04 3b [2] 20 35 [2] 0b 19 [2] 25 3b [2] 31 20 [2] 3e 3a [2] 20 27 [2] 22 26 [2] 39 20 [2] 25 27 [2] 39 08 }

  condition:
    any of them
}