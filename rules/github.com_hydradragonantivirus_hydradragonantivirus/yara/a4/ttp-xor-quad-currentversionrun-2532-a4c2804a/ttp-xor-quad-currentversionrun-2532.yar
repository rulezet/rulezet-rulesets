rule TTP_XOR_QUAD_CurrentVersionRun_2532 {
  strings:
    $key_2532 = { 76 5d [2] 52 53 [2] 79 7f [2] 57 5d [2] 43 46 [2] 4c 5c [2] 52 41 [2] 50 40 [2] 4b 46 [2] 57 41 [2] 4b 6e }

  condition:
    any of them
}