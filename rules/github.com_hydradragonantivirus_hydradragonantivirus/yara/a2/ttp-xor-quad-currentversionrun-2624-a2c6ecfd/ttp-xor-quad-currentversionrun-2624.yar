rule TTP_XOR_QUAD_CurrentVersionRun_2624 {
  strings:
    $key_2624 = { 75 4b [2] 51 45 [2] 7a 69 [2] 54 4b [2] 40 50 [2] 4f 4a [2] 51 57 [2] 53 56 [2] 48 50 [2] 54 57 [2] 48 78 }

  condition:
    any of them
}