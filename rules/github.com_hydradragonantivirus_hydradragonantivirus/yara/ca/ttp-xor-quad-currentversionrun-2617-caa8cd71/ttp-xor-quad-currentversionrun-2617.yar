rule TTP_XOR_QUAD_CurrentVersionRun_2617 {
  strings:
    $key_2617 = { 75 78 [2] 51 76 [2] 7a 5a [2] 54 78 [2] 40 63 [2] 4f 79 [2] 51 64 [2] 53 65 [2] 48 63 [2] 54 64 [2] 48 4b }

  condition:
    any of them
}