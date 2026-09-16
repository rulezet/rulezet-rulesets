rule TTP_XOR_QUAD_CurrentVersionRun_5222 {
  strings:
    $key_5222 = { 01 4d [2] 25 43 [2] 0e 6f [2] 20 4d [2] 34 56 [2] 3b 4c [2] 25 51 [2] 27 50 [2] 3c 56 [2] 20 51 [2] 3c 7e }

  condition:
    any of them
}