rule TTP_XOR_QUAD_CurrentVersionRun_1532 {
  strings:
    $key_1532 = { 46 5d [2] 62 53 [2] 49 7f [2] 67 5d [2] 73 46 [2] 7c 5c [2] 62 41 [2] 60 40 [2] 7b 46 [2] 67 41 [2] 7b 6e }

  condition:
    any of them
}