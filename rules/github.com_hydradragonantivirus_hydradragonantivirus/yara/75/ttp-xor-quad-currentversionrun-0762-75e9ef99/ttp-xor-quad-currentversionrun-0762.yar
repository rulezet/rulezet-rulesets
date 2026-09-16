rule TTP_XOR_QUAD_CurrentVersionRun_0762 {
  strings:
    $key_0762 = { 54 0d [2] 70 03 [2] 5b 2f [2] 75 0d [2] 61 16 [2] 6e 0c [2] 70 11 [2] 72 10 [2] 69 16 [2] 75 11 [2] 69 3e }

  condition:
    any of them
}