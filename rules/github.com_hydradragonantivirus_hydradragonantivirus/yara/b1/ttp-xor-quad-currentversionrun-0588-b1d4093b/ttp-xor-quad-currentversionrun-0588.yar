rule TTP_XOR_QUAD_CurrentVersionRun_0588 {
  strings:
    $key_0588 = { 56 e7 [2] 72 e9 [2] 59 c5 [2] 77 e7 [2] 63 fc [2] 6c e6 [2] 72 fb [2] 70 fa [2] 6b fc [2] 77 fb [2] 6b d4 }

  condition:
    any of them
}