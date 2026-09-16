rule TTP_XOR_QUAD_CurrentVersionRun_5764 {
  strings:
    $key_5764 = { 04 0b [2] 20 05 [2] 0b 29 [2] 25 0b [2] 31 10 [2] 3e 0a [2] 20 17 [2] 22 16 [2] 39 10 [2] 25 17 [2] 39 38 }

  condition:
    any of them
}