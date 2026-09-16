rule TTP_XOR_QUAD_CurrentVersionRun_0c32 {
  strings:
    $key_0c32 = { 5f 5d [2] 7b 53 [2] 50 7f [2] 7e 5d [2] 6a 46 [2] 65 5c [2] 7b 41 [2] 79 40 [2] 62 46 [2] 7e 41 [2] 62 6e }

  condition:
    any of them
}