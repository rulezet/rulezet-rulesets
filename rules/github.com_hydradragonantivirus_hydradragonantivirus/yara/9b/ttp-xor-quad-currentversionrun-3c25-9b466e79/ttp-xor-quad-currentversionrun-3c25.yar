rule TTP_XOR_QUAD_CurrentVersionRun_3c25 {
  strings:
    $key_3c25 = { 6f 4a [2] 4b 44 [2] 60 68 [2] 4e 4a [2] 5a 51 [2] 55 4b [2] 4b 56 [2] 49 57 [2] 52 51 [2] 4e 56 [2] 52 79 }

  condition:
    any of them
}