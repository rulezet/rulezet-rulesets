rule TTP_XOR_QUAD_CurrentVersionRun_3943 {
  strings:
    $key_3943 = { 6a 2c [2] 4e 22 [2] 65 0e [2] 4b 2c [2] 5f 37 [2] 50 2d [2] 4e 30 [2] 4c 31 [2] 57 37 [2] 4b 30 [2] 57 1f }

  condition:
    any of them
}