rule TTP_XOR_QUAD_CurrentVersionRun_3434 {
  strings:
    $key_3434 = { 67 5b [2] 43 55 [2] 68 79 [2] 46 5b [2] 52 40 [2] 5d 5a [2] 43 47 [2] 41 46 [2] 5a 40 [2] 46 47 [2] 5a 68 }

  condition:
    any of them
}