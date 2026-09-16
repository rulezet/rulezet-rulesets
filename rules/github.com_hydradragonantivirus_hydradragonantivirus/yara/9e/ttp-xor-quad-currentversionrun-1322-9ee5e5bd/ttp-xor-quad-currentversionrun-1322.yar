rule TTP_XOR_QUAD_CurrentVersionRun_1322 {
  strings:
    $key_1322 = { 40 4d [2] 64 43 [2] 4f 6f [2] 61 4d [2] 75 56 [2] 7a 4c [2] 64 51 [2] 66 50 [2] 7d 56 [2] 61 51 [2] 7d 7e }

  condition:
    any of them
}