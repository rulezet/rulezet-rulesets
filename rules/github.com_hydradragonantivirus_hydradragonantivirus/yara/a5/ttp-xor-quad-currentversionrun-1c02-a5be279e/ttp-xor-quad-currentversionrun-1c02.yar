rule TTP_XOR_QUAD_CurrentVersionRun_1c02 {
  strings:
    $key_1c02 = { 4f 6d [2] 6b 63 [2] 40 4f [2] 6e 6d [2] 7a 76 [2] 75 6c [2] 6b 71 [2] 69 70 [2] 72 76 [2] 6e 71 [2] 72 5e }

  condition:
    any of them
}