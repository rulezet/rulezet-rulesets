rule TTP_XOR_QUAD_CurrentVersionRun_5214 {
  strings:
    $key_5214 = { 01 7b [2] 25 75 [2] 0e 59 [2] 20 7b [2] 34 60 [2] 3b 7a [2] 25 67 [2] 27 66 [2] 3c 60 [2] 20 67 [2] 3c 48 }

  condition:
    any of them
}