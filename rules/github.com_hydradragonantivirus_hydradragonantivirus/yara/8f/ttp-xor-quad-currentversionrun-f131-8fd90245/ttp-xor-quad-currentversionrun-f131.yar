rule TTP_XOR_QUAD_CurrentVersionRun_f131 {
  strings:
    $key_f131 = { a2 5e [2] 86 50 [2] ad 7c [2] 83 5e [2] 97 45 [2] 98 5f [2] 86 42 [2] 84 43 [2] 9f 45 [2] 83 42 [2] 9f 6d }

  condition:
    any of them
}