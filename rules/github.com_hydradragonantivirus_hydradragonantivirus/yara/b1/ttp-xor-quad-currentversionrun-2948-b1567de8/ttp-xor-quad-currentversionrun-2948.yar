rule TTP_XOR_QUAD_CurrentVersionRun_2948 {
  strings:
    $key_2948 = { 7a 27 [2] 5e 29 [2] 75 05 [2] 5b 27 [2] 4f 3c [2] 40 26 [2] 5e 3b [2] 5c 3a [2] 47 3c [2] 5b 3b [2] 47 14 }

  condition:
    any of them
}