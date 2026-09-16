rule TTP_XOR_QUAD_CurrentVersionRun_2917 {
  strings:
    $key_2917 = { 7a 78 [2] 5e 76 [2] 75 5a [2] 5b 78 [2] 4f 63 [2] 40 79 [2] 5e 64 [2] 5c 65 [2] 47 63 [2] 5b 64 [2] 47 4b }

  condition:
    any of them
}