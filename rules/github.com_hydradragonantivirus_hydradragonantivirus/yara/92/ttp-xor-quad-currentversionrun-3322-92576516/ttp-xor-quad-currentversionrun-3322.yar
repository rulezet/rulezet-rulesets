rule TTP_XOR_QUAD_CurrentVersionRun_3322 {
  strings:
    $key_3322 = { 60 4d [2] 44 43 [2] 6f 6f [2] 41 4d [2] 55 56 [2] 5a 4c [2] 44 51 [2] 46 50 [2] 5d 56 [2] 41 51 [2] 5d 7e }

  condition:
    any of them
}