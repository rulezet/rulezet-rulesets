rule TTP_XOR_QUAD_CurrentVersionRun_5762 {
  strings:
    $key_5762 = { 04 0d [2] 20 03 [2] 0b 2f [2] 25 0d [2] 31 16 [2] 3e 0c [2] 20 11 [2] 22 10 [2] 39 16 [2] 25 11 [2] 39 3e }

  condition:
    any of them
}