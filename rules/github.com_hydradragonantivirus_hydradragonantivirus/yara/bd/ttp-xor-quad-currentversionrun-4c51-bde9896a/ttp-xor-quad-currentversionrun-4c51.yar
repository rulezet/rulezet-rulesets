rule TTP_XOR_QUAD_CurrentVersionRun_4c51 {
  strings:
    $key_4c51 = { 1f 3e [2] 3b 30 [2] 10 1c [2] 3e 3e [2] 2a 25 [2] 25 3f [2] 3b 22 [2] 39 23 [2] 22 25 [2] 3e 22 [2] 22 0d }

  condition:
    any of them
}