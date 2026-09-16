rule TTP_XOR_QUAD_CurrentVersionRun_1e02 {
  strings:
    $key_1e02 = { 4d 6d [2] 69 63 [2] 42 4f [2] 6c 6d [2] 78 76 [2] 77 6c [2] 69 71 [2] 6b 70 [2] 70 76 [2] 6c 71 [2] 70 5e }

  condition:
    any of them
}