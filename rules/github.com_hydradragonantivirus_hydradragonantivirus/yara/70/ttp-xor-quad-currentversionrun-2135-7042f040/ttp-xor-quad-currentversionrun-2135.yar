rule TTP_XOR_QUAD_CurrentVersionRun_2135 {
  strings:
    $key_2135 = { 72 5a [2] 56 54 [2] 7d 78 [2] 53 5a [2] 47 41 [2] 48 5b [2] 56 46 [2] 54 47 [2] 4f 41 [2] 53 46 [2] 4f 69 }

  condition:
    any of them
}