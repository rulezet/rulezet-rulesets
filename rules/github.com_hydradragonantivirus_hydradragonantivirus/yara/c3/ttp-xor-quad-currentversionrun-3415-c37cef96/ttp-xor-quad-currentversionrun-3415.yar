rule TTP_XOR_QUAD_CurrentVersionRun_3415 {
  strings:
    $key_3415 = { 67 7a [2] 43 74 [2] 68 58 [2] 46 7a [2] 52 61 [2] 5d 7b [2] 43 66 [2] 41 67 [2] 5a 61 [2] 46 66 [2] 5a 49 }

  condition:
    any of them
}