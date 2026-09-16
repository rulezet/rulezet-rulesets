rule TTP_XOR_QUAD_CurrentVersionRun_5832 {
  strings:
    $key_5832 = { 0b 5d [2] 2f 53 [2] 04 7f [2] 2a 5d [2] 3e 46 [2] 31 5c [2] 2f 41 [2] 2d 40 [2] 36 46 [2] 2a 41 [2] 36 6e }

  condition:
    any of them
}