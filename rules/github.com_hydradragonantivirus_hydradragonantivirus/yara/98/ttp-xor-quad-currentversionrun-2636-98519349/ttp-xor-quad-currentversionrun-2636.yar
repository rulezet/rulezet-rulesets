rule TTP_XOR_QUAD_CurrentVersionRun_2636 {
  strings:
    $key_2636 = { 75 59 [2] 51 57 [2] 7a 7b [2] 54 59 [2] 40 42 [2] 4f 58 [2] 51 45 [2] 53 44 [2] 48 42 [2] 54 45 [2] 48 6a }

  condition:
    any of them
}