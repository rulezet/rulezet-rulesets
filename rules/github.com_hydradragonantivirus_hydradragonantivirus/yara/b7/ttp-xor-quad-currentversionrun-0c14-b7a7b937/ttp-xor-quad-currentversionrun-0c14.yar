rule TTP_XOR_QUAD_CurrentVersionRun_0c14 {
  strings:
    $key_0c14 = { 5f 7b [2] 7b 75 [2] 50 59 [2] 7e 7b [2] 6a 60 [2] 65 7a [2] 7b 67 [2] 79 66 [2] 62 60 [2] 7e 67 [2] 62 48 }

  condition:
    any of them
}