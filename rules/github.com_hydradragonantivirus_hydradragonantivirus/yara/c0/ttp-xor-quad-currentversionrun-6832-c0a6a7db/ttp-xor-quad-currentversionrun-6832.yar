rule TTP_XOR_QUAD_CurrentVersionRun_6832 {
  strings:
    $key_6832 = { 3b 5d [2] 1f 53 [2] 34 7f [2] 1a 5d [2] 0e 46 [2] 01 5c [2] 1f 41 [2] 1d 40 [2] 06 46 [2] 1a 41 [2] 06 6e }

  condition:
    any of them
}