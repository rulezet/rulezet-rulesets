rule TTP_XOR_QUAD_CurrentVersionRun_1332 {
  strings:
    $key_1332 = { 40 5d [2] 64 53 [2] 4f 7f [2] 61 5d [2] 75 46 [2] 7a 5c [2] 64 41 [2] 66 40 [2] 7d 46 [2] 61 41 [2] 7d 6e }

  condition:
    any of them
}