rule TTP_XOR_QUAD_CurrentVersionRun_5532 {
  strings:
    $key_5532 = { 06 5d [2] 22 53 [2] 09 7f [2] 27 5d [2] 33 46 [2] 3c 5c [2] 22 41 [2] 20 40 [2] 3b 46 [2] 27 41 [2] 3b 6e }

  condition:
    any of them
}