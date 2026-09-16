rule TTP_XOR_QUAD_CurrentVersionRun_5131 {
  strings:
    $key_5131 = { 02 5e [2] 26 50 [2] 0d 7c [2] 23 5e [2] 37 45 [2] 38 5f [2] 26 42 [2] 24 43 [2] 3f 45 [2] 23 42 [2] 3f 6d }

  condition:
    any of them
}