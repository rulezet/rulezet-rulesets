rule TTP_XOR_QUAD_CurrentVersionRun_0915 {
  strings:
    $key_0915 = { 5a 7a [2] 7e 74 [2] 55 58 [2] 7b 7a [2] 6f 61 [2] 60 7b [2] 7e 66 [2] 7c 67 [2] 67 61 [2] 7b 66 [2] 67 49 }

  condition:
    any of them
}