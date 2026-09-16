rule TTP_XOR_QUAD_CurrentVersionRun_7a35 {
  strings:
    $key_7a35 = { 29 5a [2] 0d 54 [2] 26 78 [2] 08 5a [2] 1c 41 [2] 13 5b [2] 0d 46 [2] 0f 47 [2] 14 41 [2] 08 46 [2] 14 69 }

  condition:
    any of them
}