rule TTP_XOR_QUAD_CurrentVersionRun_2808 {
  strings:
    $key_2808 = { 7b 67 [2] 5f 69 [2] 74 45 [2] 5a 67 [2] 4e 7c [2] 41 66 [2] 5f 7b [2] 5d 7a [2] 46 7c [2] 5a 7b [2] 46 54 }

  condition:
    any of them
}