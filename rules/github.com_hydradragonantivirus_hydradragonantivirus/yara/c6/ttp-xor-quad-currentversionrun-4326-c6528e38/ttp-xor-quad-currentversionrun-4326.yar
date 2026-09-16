rule TTP_XOR_QUAD_CurrentVersionRun_4326 {
  strings:
    $key_4326 = { 10 49 [2] 34 47 [2] 1f 6b [2] 31 49 [2] 25 52 [2] 2a 48 [2] 34 55 [2] 36 54 [2] 2d 52 [2] 31 55 [2] 2d 7a }

  condition:
    any of them
}