rule TTP_XOR_QUAD_CurrentVersionRun_3633 {
  strings:
    $key_3633 = { 65 5c [2] 41 52 [2] 6a 7e [2] 44 5c [2] 50 47 [2] 5f 5d [2] 41 40 [2] 43 41 [2] 58 47 [2] 44 40 [2] 58 6f }

  condition:
    any of them
}