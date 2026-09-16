rule TTP_XOR_QUAD_CurrentVersionRun_3133 {
  strings:
    $key_3133 = { 62 5c [2] 46 52 [2] 6d 7e [2] 43 5c [2] 57 47 [2] 58 5d [2] 46 40 [2] 44 41 [2] 5f 47 [2] 43 40 [2] 5f 6f }

  condition:
    any of them
}