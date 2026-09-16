rule TTP_XOR_QUAD_CurrentVersionRun_4302 {
  strings:
    $key_4302 = { 10 6d [2] 34 63 [2] 1f 4f [2] 31 6d [2] 25 76 [2] 2a 6c [2] 34 71 [2] 36 70 [2] 2d 76 [2] 31 71 [2] 2d 5e }

  condition:
    any of them
}