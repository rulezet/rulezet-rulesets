rule TTP_XOR_QUAD_CurrentVersionRun_5132 {
  strings:
    $key_5132 = { 02 5d [2] 26 53 [2] 0d 7f [2] 23 5d [2] 37 46 [2] 38 5c [2] 26 41 [2] 24 40 [2] 3f 46 [2] 23 41 [2] 3f 6e }

  condition:
    any of them
}