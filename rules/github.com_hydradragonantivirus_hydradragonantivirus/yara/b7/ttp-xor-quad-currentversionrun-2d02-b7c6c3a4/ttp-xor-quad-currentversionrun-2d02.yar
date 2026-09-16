rule TTP_XOR_QUAD_CurrentVersionRun_2d02 {
  strings:
    $key_2d02 = { 7e 6d [2] 5a 63 [2] 71 4f [2] 5f 6d [2] 4b 76 [2] 44 6c [2] 5a 71 [2] 58 70 [2] 43 76 [2] 5f 71 [2] 43 5e }

  condition:
    any of them
}