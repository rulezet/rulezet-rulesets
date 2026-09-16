rule TTP_XOR_QUAD_CurrentVersionRun_0b02 {
  strings:
    $key_0b02 = { 58 6d [2] 7c 63 [2] 57 4f [2] 79 6d [2] 6d 76 [2] 62 6c [2] 7c 71 [2] 7e 70 [2] 65 76 [2] 79 71 [2] 65 5e }

  condition:
    any of them
}