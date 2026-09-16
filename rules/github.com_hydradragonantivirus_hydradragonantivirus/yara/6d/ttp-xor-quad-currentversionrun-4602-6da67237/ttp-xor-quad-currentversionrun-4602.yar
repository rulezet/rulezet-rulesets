rule TTP_XOR_QUAD_CurrentVersionRun_4602 {
  strings:
    $key_4602 = { 15 6d [2] 31 63 [2] 1a 4f [2] 34 6d [2] 20 76 [2] 2f 6c [2] 31 71 [2] 33 70 [2] 28 76 [2] 34 71 [2] 28 5e }

  condition:
    any of them
}