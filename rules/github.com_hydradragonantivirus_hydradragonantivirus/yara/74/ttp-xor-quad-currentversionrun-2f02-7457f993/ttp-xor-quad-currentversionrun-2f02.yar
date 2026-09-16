rule TTP_XOR_QUAD_CurrentVersionRun_2f02 {
  strings:
    $key_2f02 = { 7c 6d [2] 58 63 [2] 73 4f [2] 5d 6d [2] 49 76 [2] 46 6c [2] 58 71 [2] 5a 70 [2] 41 76 [2] 5d 71 [2] 41 5e }

  condition:
    any of them
}