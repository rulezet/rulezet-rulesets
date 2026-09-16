rule TTP_XOR_QUAD_CurrentVersionRun_2765 {
  strings:
    $key_2765 = { 74 0a [2] 50 04 [2] 7b 28 [2] 55 0a [2] 41 11 [2] 4e 0b [2] 50 16 [2] 52 17 [2] 49 11 [2] 55 16 [2] 49 39 }

  condition:
    any of them
}