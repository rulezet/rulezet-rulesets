rule TTP_XOR_QUAD_CurrentVersionRun_092b {
  strings:
    $key_092b = { 5a 44 [2] 7e 4a [2] 55 66 [2] 7b 44 [2] 6f 5f [2] 60 45 [2] 7e 58 [2] 7c 59 [2] 67 5f [2] 7b 58 [2] 67 77 }

  condition:
    any of them
}