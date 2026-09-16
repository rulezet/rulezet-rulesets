rule TTP_XOR_QUAD_CurrentVersionRun_5717 {
  strings:
    $key_5717 = { 04 78 [2] 20 76 [2] 0b 5a [2] 25 78 [2] 31 63 [2] 3e 79 [2] 20 64 [2] 22 65 [2] 39 63 [2] 25 64 [2] 39 4b }

  condition:
    any of them
}