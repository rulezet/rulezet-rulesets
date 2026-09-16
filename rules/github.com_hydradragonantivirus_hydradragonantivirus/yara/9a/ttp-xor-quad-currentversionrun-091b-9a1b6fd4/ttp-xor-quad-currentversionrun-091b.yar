rule TTP_XOR_QUAD_CurrentVersionRun_091b {
  strings:
    $key_091b = { 5a 74 [2] 7e 7a [2] 55 56 [2] 7b 74 [2] 6f 6f [2] 60 75 [2] 7e 68 [2] 7c 69 [2] 67 6f [2] 7b 68 [2] 67 47 }

  condition:
    any of them
}