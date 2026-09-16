rule TTP_XOR_QUAD_CurrentVersionRun_3c45 {
  strings:
    $key_3c45 = { 6f 2a [2] 4b 24 [2] 60 08 [2] 4e 2a [2] 5a 31 [2] 55 2b [2] 4b 36 [2] 49 37 [2] 52 31 [2] 4e 36 [2] 52 19 }

  condition:
    any of them
}