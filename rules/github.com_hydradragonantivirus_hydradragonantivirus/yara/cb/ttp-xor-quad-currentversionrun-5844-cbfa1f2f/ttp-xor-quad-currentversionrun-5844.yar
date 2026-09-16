rule TTP_XOR_QUAD_CurrentVersionRun_5844 {
  strings:
    $key_5844 = { 0b 2b [2] 2f 25 [2] 04 09 [2] 2a 2b [2] 3e 30 [2] 31 2a [2] 2f 37 [2] 2d 36 [2] 36 30 [2] 2a 37 [2] 36 18 }

  condition:
    any of them
}