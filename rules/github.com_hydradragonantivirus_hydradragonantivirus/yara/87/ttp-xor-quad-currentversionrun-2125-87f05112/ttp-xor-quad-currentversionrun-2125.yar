rule TTP_XOR_QUAD_CurrentVersionRun_2125 {
  strings:
    $key_2125 = { 72 4a [2] 56 44 [2] 7d 68 [2] 53 4a [2] 47 51 [2] 48 4b [2] 56 56 [2] 54 57 [2] 4f 51 [2] 53 56 [2] 4f 79 }

  condition:
    any of them
}