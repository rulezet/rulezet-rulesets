rule TTP_XOR_QUAD_CurrentVersionRun_0844 {
  strings:
    $key_0844 = { 5b 2b [2] 7f 25 [2] 54 09 [2] 7a 2b [2] 6e 30 [2] 61 2a [2] 7f 37 [2] 7d 36 [2] 66 30 [2] 7a 37 [2] 66 18 }

  condition:
    any of them
}