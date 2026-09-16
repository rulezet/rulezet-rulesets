rule TTP_XOR_QUAD_CurrentVersionRun_6bfa {
  strings:
    $key_6bfa = { 38 95 [2] 1c 9b [2] 37 b7 [2] 19 95 [2] 0d 8e [2] 02 94 [2] 1c 89 [2] 1e 88 [2] 05 8e [2] 19 89 [2] 05 a6 }

  condition:
    any of them
}