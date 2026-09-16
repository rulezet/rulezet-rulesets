rule TTP_XOR_QUAD_CurrentVersionRun_2834 {
  strings:
    $key_2834 = { 7b 5b [2] 5f 55 [2] 74 79 [2] 5a 5b [2] 4e 40 [2] 41 5a [2] 5f 47 [2] 5d 46 [2] 46 40 [2] 5a 47 [2] 46 68 }

  condition:
    any of them
}