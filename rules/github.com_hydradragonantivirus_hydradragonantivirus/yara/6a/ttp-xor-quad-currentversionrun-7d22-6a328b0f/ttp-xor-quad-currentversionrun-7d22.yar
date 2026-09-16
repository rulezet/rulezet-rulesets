rule TTP_XOR_QUAD_CurrentVersionRun_7d22 {
  strings:
    $key_7d22 = { 2e 4d [2] 0a 43 [2] 21 6f [2] 0f 4d [2] 1b 56 [2] 14 4c [2] 0a 51 [2] 08 50 [2] 13 56 [2] 0f 51 [2] 13 7e }

  condition:
    any of them
}