rule TTP_XOR_QUAD_CurrentVersionRun_e336 {
  strings:
    $key_e336 = { b0 59 [2] 94 57 [2] bf 7b [2] 91 59 [2] 85 42 [2] 8a 58 [2] 94 45 [2] 96 44 [2] 8d 42 [2] 91 45 [2] 8d 6a }

  condition:
    any of them
}