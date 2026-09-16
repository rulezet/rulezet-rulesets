rule TTP_XOR_QUAD_CurrentVersionRun_6509 {
  strings:
    $key_6509 = { 36 66 [2] 12 68 [2] 39 44 [2] 17 66 [2] 03 7d [2] 0c 67 [2] 12 7a [2] 10 7b [2] 0b 7d [2] 17 7a [2] 0b 55 }

  condition:
    any of them
}