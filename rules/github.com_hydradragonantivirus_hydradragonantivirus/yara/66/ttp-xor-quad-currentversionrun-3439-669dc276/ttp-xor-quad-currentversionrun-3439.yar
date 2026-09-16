rule TTP_XOR_QUAD_CurrentVersionRun_3439 {
  strings:
    $key_3439 = { 67 56 [2] 43 58 [2] 68 74 [2] 46 56 [2] 52 4d [2] 5d 57 [2] 43 4a [2] 41 4b [2] 5a 4d [2] 46 4a [2] 5a 65 }

  condition:
    any of them
}