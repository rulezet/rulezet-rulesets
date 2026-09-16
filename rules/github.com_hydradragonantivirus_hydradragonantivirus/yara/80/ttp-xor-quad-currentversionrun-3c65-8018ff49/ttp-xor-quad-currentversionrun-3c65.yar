rule TTP_XOR_QUAD_CurrentVersionRun_3c65 {
  strings:
    $key_3c65 = { 6f 0a [2] 4b 04 [2] 60 28 [2] 4e 0a [2] 5a 11 [2] 55 0b [2] 4b 16 [2] 49 17 [2] 52 11 [2] 4e 16 [2] 52 39 }

  condition:
    any of them
}