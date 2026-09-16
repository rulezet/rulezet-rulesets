rule TTP_XOR_QUAD_CurrentVersionRun_2a32 {
  strings:
    $key_2a32 = { 79 5d [2] 5d 53 [2] 76 7f [2] 58 5d [2] 4c 46 [2] 43 5c [2] 5d 41 [2] 5f 40 [2] 44 46 [2] 58 41 [2] 44 6e }

  condition:
    any of them
}