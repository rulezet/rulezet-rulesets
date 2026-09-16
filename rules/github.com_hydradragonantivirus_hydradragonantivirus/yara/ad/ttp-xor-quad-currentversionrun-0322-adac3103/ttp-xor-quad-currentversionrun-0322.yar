rule TTP_XOR_QUAD_CurrentVersionRun_0322 {
  strings:
    $key_0322 = { 50 4d [2] 74 43 [2] 5f 6f [2] 71 4d [2] 65 56 [2] 6a 4c [2] 74 51 [2] 76 50 [2] 6d 56 [2] 71 51 [2] 6d 7e }

  condition:
    any of them
}