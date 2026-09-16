rule TTP_XOR_QUAD_CurrentVersionRun_1426 {
  strings:
    $key_1426 = { 47 49 [2] 63 47 [2] 48 6b [2] 66 49 [2] 72 52 [2] 7d 48 [2] 63 55 [2] 61 54 [2] 7a 52 [2] 66 55 [2] 7a 7a }

  condition:
    any of them
}