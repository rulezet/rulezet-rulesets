rule TTP_XOR_QUAD_CurrentVersionRun_0859 {
  strings:
    $key_0859 = { 5b 36 [2] 7f 38 [2] 54 14 [2] 7a 36 [2] 6e 2d [2] 61 37 [2] 7f 2a [2] 7d 2b [2] 66 2d [2] 7a 2a [2] 66 05 }

  condition:
    any of them
}