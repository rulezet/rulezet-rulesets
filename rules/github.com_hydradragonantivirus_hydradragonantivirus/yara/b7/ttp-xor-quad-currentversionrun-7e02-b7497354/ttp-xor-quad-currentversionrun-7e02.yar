rule TTP_XOR_QUAD_CurrentVersionRun_7e02 {
  strings:
    $key_7e02 = { 2d 6d [2] 09 63 [2] 22 4f [2] 0c 6d [2] 18 76 [2] 17 6c [2] 09 71 [2] 0b 70 [2] 10 76 [2] 0c 71 [2] 10 5e }

  condition:
    any of them
}