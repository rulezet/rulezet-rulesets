rule TTP_XOR_QUAD_CurrentVersionRun_e326 {
  strings:
    $key_e326 = { b0 49 [2] 94 47 [2] bf 6b [2] 91 49 [2] 85 52 [2] 8a 48 [2] 94 55 [2] 96 54 [2] 8d 52 [2] 91 55 [2] 8d 7a }

  condition:
    any of them
}