rule TTP_XOR_QUAD_CurrentVersionRun_5602 {
  strings:
    $key_5602 = { 05 6d [2] 21 63 [2] 0a 4f [2] 24 6d [2] 30 76 [2] 3f 6c [2] 21 71 [2] 23 70 [2] 38 76 [2] 24 71 [2] 38 5e }

  condition:
    any of them
}