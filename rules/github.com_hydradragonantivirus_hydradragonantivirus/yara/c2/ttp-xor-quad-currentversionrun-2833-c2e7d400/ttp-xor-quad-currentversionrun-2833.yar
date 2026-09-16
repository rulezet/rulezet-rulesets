rule TTP_XOR_QUAD_CurrentVersionRun_2833 {
  strings:
    $key_2833 = { 7b 5c [2] 5f 52 [2] 74 7e [2] 5a 5c [2] 4e 47 [2] 41 5d [2] 5f 40 [2] 5d 41 [2] 46 47 [2] 5a 40 [2] 46 6f }

  condition:
    any of them
}