rule TTP_XOR_QUAD_CurrentVersionRun_6534 {
  strings:
    $key_6534 = { 36 5b [2] 12 55 [2] 39 79 [2] 17 5b [2] 03 40 [2] 0c 5a [2] 12 47 [2] 10 46 [2] 0b 40 [2] 17 47 [2] 0b 68 }

  condition:
    any of them
}