rule TTP_XOR_QUAD_CurrentVersionRun_3631 {
  strings:
    $key_3631 = { 65 5e [2] 41 50 [2] 6a 7c [2] 44 5e [2] 50 45 [2] 5f 5f [2] 41 42 [2] 43 43 [2] 58 45 [2] 44 42 [2] 58 6d }

  condition:
    any of them
}