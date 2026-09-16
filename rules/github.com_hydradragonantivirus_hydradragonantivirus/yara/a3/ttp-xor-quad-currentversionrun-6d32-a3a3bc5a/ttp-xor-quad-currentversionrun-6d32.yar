rule TTP_XOR_QUAD_CurrentVersionRun_6d32 {
  strings:
    $key_6d32 = { 3e 5d [2] 1a 53 [2] 31 7f [2] 1f 5d [2] 0b 46 [2] 04 5c [2] 1a 41 [2] 18 40 [2] 03 46 [2] 1f 41 [2] 03 6e }

  condition:
    any of them
}