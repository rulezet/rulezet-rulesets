rule TTP_XOR_QUAD_CurrentVersionRun_0c08 {
  strings:
    $key_0c08 = { 5f 67 [2] 7b 69 [2] 50 45 [2] 7e 67 [2] 6a 7c [2] 65 66 [2] 7b 7b [2] 79 7a [2] 62 7c [2] 7e 7b [2] 62 54 }

  condition:
    any of them
}