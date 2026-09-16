rule TTP_XOR_QUAD_CurrentVersionRun_1c32 {
  strings:
    $key_1c32 = { 4f 5d [2] 6b 53 [2] 40 7f [2] 6e 5d [2] 7a 46 [2] 75 5c [2] 6b 41 [2] 69 40 [2] 72 46 [2] 6e 41 [2] 72 6e }

  condition:
    any of them
}