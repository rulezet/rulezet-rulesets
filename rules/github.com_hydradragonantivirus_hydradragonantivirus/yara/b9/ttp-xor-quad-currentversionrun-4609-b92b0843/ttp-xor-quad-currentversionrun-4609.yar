rule TTP_XOR_QUAD_CurrentVersionRun_4609 {
  strings:
    $key_4609 = { 15 66 [2] 31 68 [2] 1a 44 [2] 34 66 [2] 20 7d [2] 2f 67 [2] 31 7a [2] 33 7b [2] 28 7d [2] 34 7a [2] 28 55 }

  condition:
    any of them
}