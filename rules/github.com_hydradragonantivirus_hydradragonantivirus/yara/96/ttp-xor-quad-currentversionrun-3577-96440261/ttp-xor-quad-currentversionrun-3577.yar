rule TTP_XOR_QUAD_CurrentVersionRun_3577 {
  strings:
    $key_3577 = { 66 18 [2] 42 16 [2] 69 3a [2] 47 18 [2] 53 03 [2] 5c 19 [2] 42 04 [2] 40 05 [2] 5b 03 [2] 47 04 [2] 5b 2b }

  condition:
    any of them
}