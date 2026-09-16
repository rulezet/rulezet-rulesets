rule TTP_XOR_QUAD_CurrentVersionRun_3c78 {
  strings:
    $key_3c78 = { 6f 17 [2] 4b 19 [2] 60 35 [2] 4e 17 [2] 5a 0c [2] 55 16 [2] 4b 0b [2] 49 0a [2] 52 0c [2] 4e 0b [2] 52 24 }

  condition:
    any of them
}