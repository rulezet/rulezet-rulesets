rule TTP_XOR_QUAD_CurrentVersionRun_0835 {
  strings:
    $key_0835 = { 5b 5a [2] 7f 54 [2] 54 78 [2] 7a 5a [2] 6e 41 [2] 61 5b [2] 7f 46 [2] 7d 47 [2] 66 41 [2] 7a 46 [2] 66 69 }

  condition:
    any of them
}