rule TTP_XOR_QUAD_CurrentVersionRun_3a09 {
  strings:
    $key_3a09 = { 69 66 [2] 4d 68 [2] 66 44 [2] 48 66 [2] 5c 7d [2] 53 67 [2] 4d 7a [2] 4f 7b [2] 54 7d [2] 48 7a [2] 54 55 }

  condition:
    any of them
}