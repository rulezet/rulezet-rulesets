rule TTP_XOR_QUAD_CurrentVersionRun_2602 {
  strings:
    $key_2602 = { 75 6d [2] 51 63 [2] 7a 4f [2] 54 6d [2] 40 76 [2] 4f 6c [2] 51 71 [2] 53 70 [2] 48 76 [2] 54 71 [2] 48 5e }

  condition:
    any of them
}