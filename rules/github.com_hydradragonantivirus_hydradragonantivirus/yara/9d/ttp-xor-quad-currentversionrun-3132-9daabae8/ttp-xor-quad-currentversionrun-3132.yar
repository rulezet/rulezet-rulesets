rule TTP_XOR_QUAD_CurrentVersionRun_3132 {
  strings:
    $key_3132 = { 62 5d [2] 46 53 [2] 6d 7f [2] 43 5d [2] 57 46 [2] 58 5c [2] 46 41 [2] 44 40 [2] 5f 46 [2] 43 41 [2] 5f 6e }

  condition:
    any of them
}