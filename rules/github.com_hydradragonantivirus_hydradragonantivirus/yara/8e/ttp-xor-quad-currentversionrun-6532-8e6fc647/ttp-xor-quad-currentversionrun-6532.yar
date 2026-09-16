rule TTP_XOR_QUAD_CurrentVersionRun_6532 {
  strings:
    $key_6532 = { 36 5d [2] 12 53 [2] 39 7f [2] 17 5d [2] 03 46 [2] 0c 5c [2] 12 41 [2] 10 40 [2] 0b 46 [2] 17 41 [2] 0b 6e }

  condition:
    any of them
}