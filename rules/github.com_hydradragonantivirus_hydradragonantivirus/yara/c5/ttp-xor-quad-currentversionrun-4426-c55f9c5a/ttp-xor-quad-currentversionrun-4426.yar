rule TTP_XOR_QUAD_CurrentVersionRun_4426 {
  strings:
    $key_4426 = { 17 49 [2] 33 47 [2] 18 6b [2] 36 49 [2] 22 52 [2] 2d 48 [2] 33 55 [2] 31 54 [2] 2a 52 [2] 36 55 [2] 2a 7a }

  condition:
    any of them
}