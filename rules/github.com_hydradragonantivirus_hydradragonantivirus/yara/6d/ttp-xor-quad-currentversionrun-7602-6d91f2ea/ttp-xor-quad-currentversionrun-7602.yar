rule TTP_XOR_QUAD_CurrentVersionRun_7602 {
  strings:
    $key_7602 = { 25 6d [2] 01 63 [2] 2a 4f [2] 04 6d [2] 10 76 [2] 1f 6c [2] 01 71 [2] 03 70 [2] 18 76 [2] 04 71 [2] 18 5e }

  condition:
    any of them
}