rule TTP_XOR_QUAD_CurrentVersionRun_3209 {
  strings:
    $key_3209 = { 61 66 [2] 45 68 [2] 6e 44 [2] 40 66 [2] 54 7d [2] 5b 67 [2] 45 7a [2] 47 7b [2] 5c 7d [2] 40 7a [2] 5c 55 }

  condition:
    any of them
}