rule TTP_XOR_QUAD_CurrentVersionRun_7662 {
  strings:
    $key_7662 = { 25 0d [2] 01 03 [2] 2a 2f [2] 04 0d [2] 10 16 [2] 1f 0c [2] 01 11 [2] 03 10 [2] 18 16 [2] 04 11 [2] 18 3e }

  condition:
    any of them
}