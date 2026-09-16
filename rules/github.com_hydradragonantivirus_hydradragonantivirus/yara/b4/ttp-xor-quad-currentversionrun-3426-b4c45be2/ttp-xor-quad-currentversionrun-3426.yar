rule TTP_XOR_QUAD_CurrentVersionRun_3426 {
  strings:
    $key_3426 = { 67 49 [2] 43 47 [2] 68 6b [2] 46 49 [2] 52 52 [2] 5d 48 [2] 43 55 [2] 41 54 [2] 5a 52 [2] 46 55 [2] 5a 7a }

  condition:
    any of them
}