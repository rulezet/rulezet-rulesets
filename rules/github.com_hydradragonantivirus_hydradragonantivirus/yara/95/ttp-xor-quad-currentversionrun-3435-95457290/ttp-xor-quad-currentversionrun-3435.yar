rule TTP_XOR_QUAD_CurrentVersionRun_3435 {
  strings:
    $key_3435 = { 67 5a [2] 43 54 [2] 68 78 [2] 46 5a [2] 52 41 [2] 5d 5b [2] 43 46 [2] 41 47 [2] 5a 41 [2] 46 46 [2] 5a 69 }

  condition:
    any of them
}