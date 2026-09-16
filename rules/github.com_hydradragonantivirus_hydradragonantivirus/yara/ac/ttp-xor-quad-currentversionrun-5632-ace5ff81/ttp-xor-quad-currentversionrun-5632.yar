rule TTP_XOR_QUAD_CurrentVersionRun_5632 {
  strings:
    $key_5632 = { 05 5d [2] 21 53 [2] 0a 7f [2] 24 5d [2] 30 46 [2] 3f 5c [2] 21 41 [2] 23 40 [2] 38 46 [2] 24 41 [2] 38 6e }

  condition:
    any of them
}