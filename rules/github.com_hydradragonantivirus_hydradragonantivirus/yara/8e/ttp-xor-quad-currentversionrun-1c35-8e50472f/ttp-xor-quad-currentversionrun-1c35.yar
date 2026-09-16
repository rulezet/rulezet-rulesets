rule TTP_XOR_QUAD_CurrentVersionRun_1c35 {
  strings:
    $key_1c35 = { 4f 5a [2] 6b 54 [2] 40 78 [2] 6e 5a [2] 7a 41 [2] 75 5b [2] 6b 46 [2] 69 47 [2] 72 41 [2] 6e 46 [2] 72 69 }

  condition:
    any of them
}