rule TTP_XOR_QUAD_CurrentVersionRun_2805 {
  strings:
    $key_2805 = { 7b 6a [2] 5f 64 [2] 74 48 [2] 5a 6a [2] 4e 71 [2] 41 6b [2] 5f 76 [2] 5d 77 [2] 46 71 [2] 5a 76 [2] 46 59 }

  condition:
    any of them
}