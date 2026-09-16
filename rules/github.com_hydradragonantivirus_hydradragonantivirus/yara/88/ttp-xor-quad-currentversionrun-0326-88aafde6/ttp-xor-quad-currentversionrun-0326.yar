rule TTP_XOR_QUAD_CurrentVersionRun_0326 {
  strings:
    $key_0326 = { 50 49 [2] 74 47 [2] 5f 6b [2] 71 49 [2] 65 52 [2] 6a 48 [2] 74 55 [2] 76 54 [2] 6d 52 [2] 71 55 [2] 6d 7a }

  condition:
    any of them
}