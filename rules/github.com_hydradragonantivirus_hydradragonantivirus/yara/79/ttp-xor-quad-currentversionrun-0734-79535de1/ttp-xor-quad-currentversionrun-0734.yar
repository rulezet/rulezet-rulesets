rule TTP_XOR_QUAD_CurrentVersionRun_0734 {
  strings:
    $key_0734 = { 54 5b [2] 70 55 [2] 5b 79 [2] 75 5b [2] 61 40 [2] 6e 5a [2] 70 47 [2] 72 46 [2] 69 40 [2] 75 47 [2] 69 68 }

  condition:
    any of them
}