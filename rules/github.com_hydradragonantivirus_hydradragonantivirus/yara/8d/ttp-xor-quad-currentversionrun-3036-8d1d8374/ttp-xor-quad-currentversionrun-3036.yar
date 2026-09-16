rule TTP_XOR_QUAD_CurrentVersionRun_3036 {
  strings:
    $key_3036 = { 63 59 [2] 47 57 [2] 6c 7b [2] 42 59 [2] 56 42 [2] 59 58 [2] 47 45 [2] 45 44 [2] 5e 42 [2] 42 45 [2] 5e 6a }

  condition:
    any of them
}