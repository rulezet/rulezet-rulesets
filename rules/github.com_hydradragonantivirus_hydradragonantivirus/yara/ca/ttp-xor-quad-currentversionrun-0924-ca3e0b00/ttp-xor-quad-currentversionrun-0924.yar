rule TTP_XOR_QUAD_CurrentVersionRun_0924 {
  strings:
    $key_0924 = { 5a 4b [2] 7e 45 [2] 55 69 [2] 7b 4b [2] 6f 50 [2] 60 4a [2] 7e 57 [2] 7c 56 [2] 67 50 [2] 7b 57 [2] 67 78 }

  condition:
    any of them
}