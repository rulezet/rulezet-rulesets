rule TTP_XOR_QUAD_CurrentVersionRun_1962 {
  strings:
    $key_1962 = { 4a 0d [2] 6e 03 [2] 45 2f [2] 6b 0d [2] 7f 16 [2] 70 0c [2] 6e 11 [2] 6c 10 [2] 77 16 [2] 6b 11 [2] 77 3e }

  condition:
    any of them
}