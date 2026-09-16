rule TTP_XOR_QUAD_CurrentVersionRun_3862 {
  strings:
    $key_3862 = { 6b 0d [2] 4f 03 [2] 64 2f [2] 4a 0d [2] 5e 16 [2] 51 0c [2] 4f 11 [2] 4d 10 [2] 56 16 [2] 4a 11 [2] 56 3e }

  condition:
    any of them
}