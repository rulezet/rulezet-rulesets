rule TTP_XOR_QUAD_CurrentVersionRun_5065 {
  strings:
    $key_5065 = { 03 0a [2] 27 04 [2] 0c 28 [2] 22 0a [2] 36 11 [2] 39 0b [2] 27 16 [2] 25 17 [2] 3e 11 [2] 22 16 [2] 3e 39 }

  condition:
    any of them
}