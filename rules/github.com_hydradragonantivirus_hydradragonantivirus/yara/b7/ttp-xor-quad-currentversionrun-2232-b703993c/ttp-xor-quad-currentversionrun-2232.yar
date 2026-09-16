rule TTP_XOR_QUAD_CurrentVersionRun_2232 {
  strings:
    $key_2232 = { 71 5d [2] 55 53 [2] 7e 7f [2] 50 5d [2] 44 46 [2] 4b 5c [2] 55 41 [2] 57 40 [2] 4c 46 [2] 50 41 [2] 4c 6e }

  condition:
    any of them
}