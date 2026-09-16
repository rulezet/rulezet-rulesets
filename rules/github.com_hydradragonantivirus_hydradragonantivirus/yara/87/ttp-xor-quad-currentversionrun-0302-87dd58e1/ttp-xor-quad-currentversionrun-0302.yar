rule TTP_XOR_QUAD_CurrentVersionRun_0302 {
  strings:
    $key_0302 = { 50 6d [2] 74 63 [2] 5f 4f [2] 71 6d [2] 65 76 [2] 6a 6c [2] 74 71 [2] 76 70 [2] 6d 76 [2] 71 71 [2] 6d 5e }

  condition:
    any of them
}