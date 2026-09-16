rule TTP_XOR_QUAD_CurrentVersionRun_7914 {
  strings:
    $key_7914 = { 2a 7b [2] 0e 75 [2] 25 59 [2] 0b 7b [2] 1f 60 [2] 10 7a [2] 0e 67 [2] 0c 66 [2] 17 60 [2] 0b 67 [2] 17 48 }

  condition:
    any of them
}