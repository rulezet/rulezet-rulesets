rule TTP_XOR_QUAD_CurrentVersionRun_3632 {
  strings:
    $key_3632 = { 65 5d [2] 41 53 [2] 6a 7f [2] 44 5d [2] 50 46 [2] 5f 5c [2] 41 41 [2] 43 40 [2] 58 46 [2] 44 41 [2] 58 6e }

  condition:
    any of them
}