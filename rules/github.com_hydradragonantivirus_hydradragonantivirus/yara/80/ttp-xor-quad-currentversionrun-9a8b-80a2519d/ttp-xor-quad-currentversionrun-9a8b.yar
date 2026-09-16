rule TTP_XOR_QUAD_CurrentVersionRun_9a8b {
  strings:
    $key_9a8b = { c9 e4 [2] ed ea [2] c6 c6 [2] e8 e4 [2] fc ff [2] f3 e5 [2] ed f8 [2] ef f9 [2] f4 ff [2] e8 f8 [2] f4 d7 }

  condition:
    any of them
}