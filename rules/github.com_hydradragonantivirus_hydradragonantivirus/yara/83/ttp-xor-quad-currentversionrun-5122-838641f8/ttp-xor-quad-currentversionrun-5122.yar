rule TTP_XOR_QUAD_CurrentVersionRun_5122 {
  strings:
    $key_5122 = { 02 4d [2] 26 43 [2] 0d 6f [2] 23 4d [2] 37 56 [2] 38 4c [2] 26 51 [2] 24 50 [2] 3f 56 [2] 23 51 [2] 3f 7e }

  condition:
    any of them
}