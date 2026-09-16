rule TTP_XOR_QUAD_CurrentVersionRun_0829 {
  strings:
    $key_0829 = { 5b 46 [2] 7f 48 [2] 54 64 [2] 7a 46 [2] 6e 5d [2] 61 47 [2] 7f 5a [2] 7d 5b [2] 66 5d [2] 7a 5a [2] 66 75 }

  condition:
    any of them
}