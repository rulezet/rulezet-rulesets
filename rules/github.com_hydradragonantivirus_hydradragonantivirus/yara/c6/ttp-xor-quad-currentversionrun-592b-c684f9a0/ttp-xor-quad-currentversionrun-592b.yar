rule TTP_XOR_QUAD_CurrentVersionRun_592b {
  strings:
    $key_592b = { 0a 44 [2] 2e 4a [2] 05 66 [2] 2b 44 [2] 3f 5f [2] 30 45 [2] 2e 58 [2] 2c 59 [2] 37 5f [2] 2b 58 [2] 37 77 }

  condition:
    any of them
}