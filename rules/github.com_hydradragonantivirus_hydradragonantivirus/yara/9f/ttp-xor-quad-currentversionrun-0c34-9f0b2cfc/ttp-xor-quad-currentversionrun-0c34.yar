rule TTP_XOR_QUAD_CurrentVersionRun_0c34 {
  strings:
    $key_0c34 = { 5f 5b [2] 7b 55 [2] 50 79 [2] 7e 5b [2] 6a 40 [2] 65 5a [2] 7b 47 [2] 79 46 [2] 62 40 [2] 7e 47 [2] 62 68 }

  condition:
    any of them
}