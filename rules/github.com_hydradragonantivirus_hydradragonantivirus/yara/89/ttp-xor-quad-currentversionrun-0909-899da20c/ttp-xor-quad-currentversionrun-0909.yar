rule TTP_XOR_QUAD_CurrentVersionRun_0909 {
  strings:
    $key_0909 = { 5a 66 [2] 7e 68 [2] 55 44 [2] 7b 66 [2] 6f 7d [2] 60 67 [2] 7e 7a [2] 7c 7b [2] 67 7d [2] 7b 7a [2] 67 55 }

  condition:
    any of them
}