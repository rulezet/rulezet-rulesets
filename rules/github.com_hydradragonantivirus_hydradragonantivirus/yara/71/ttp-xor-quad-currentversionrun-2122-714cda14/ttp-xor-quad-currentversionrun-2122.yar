rule TTP_XOR_QUAD_CurrentVersionRun_2122 {
  strings:
    $key_2122 = { 72 4d [2] 56 43 [2] 7d 6f [2] 53 4d [2] 47 56 [2] 48 4c [2] 56 51 [2] 54 50 [2] 4f 56 [2] 53 51 [2] 4f 7e }

  condition:
    any of them
}