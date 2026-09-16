rule TTP_XOR_QUAD_CurrentVersionRun_2812 {
  strings:
    $key_2812 = { 7b 7d [2] 5f 73 [2] 74 5f [2] 5a 7d [2] 4e 66 [2] 41 7c [2] 5f 61 [2] 5d 60 [2] 46 66 [2] 5a 61 [2] 46 4e }

  condition:
    any of them
}