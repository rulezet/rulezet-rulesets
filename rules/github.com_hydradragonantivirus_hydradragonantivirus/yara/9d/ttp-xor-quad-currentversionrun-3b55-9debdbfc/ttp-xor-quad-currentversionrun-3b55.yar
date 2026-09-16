rule TTP_XOR_QUAD_CurrentVersionRun_3b55 {
  strings:
    $key_3b55 = { 68 3a [2] 4c 34 [2] 67 18 [2] 49 3a [2] 5d 21 [2] 52 3b [2] 4c 26 [2] 4e 27 [2] 55 21 [2] 49 26 [2] 55 09 }

  condition:
    any of them
}