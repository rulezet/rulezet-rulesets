rule TTP_XOR_QUAD_CurrentVersionRun_7f22 {
  strings:
    $key_7f22 = { 2c 4d [2] 08 43 [2] 23 6f [2] 0d 4d [2] 19 56 [2] 16 4c [2] 08 51 [2] 0a 50 [2] 11 56 [2] 0d 51 [2] 11 7e }

  condition:
    any of them
}