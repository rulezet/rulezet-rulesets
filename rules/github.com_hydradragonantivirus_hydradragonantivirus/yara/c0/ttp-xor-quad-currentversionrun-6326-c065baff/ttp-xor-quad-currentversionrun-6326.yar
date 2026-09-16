rule TTP_XOR_QUAD_CurrentVersionRun_6326 {
  strings:
    $key_6326 = { 30 49 [2] 14 47 [2] 3f 6b [2] 11 49 [2] 05 52 [2] 0a 48 [2] 14 55 [2] 16 54 [2] 0d 52 [2] 11 55 [2] 0d 7a }

  condition:
    any of them
}