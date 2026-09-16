rule TTP_XOR_QUAD_CurrentVersionRun_2609 {
  strings:
    $key_2609 = { 75 66 [2] 51 68 [2] 7a 44 [2] 54 66 [2] 40 7d [2] 4f 67 [2] 51 7a [2] 53 7b [2] 48 7d [2] 54 7a [2] 48 55 }

  condition:
    any of them
}