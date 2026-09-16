rule TTP_XOR_QUAD_CurrentVersionRun_f551 {
  strings:
    $key_f551 = { a6 3e [2] 82 30 [2] a9 1c [2] 87 3e [2] 93 25 [2] 9c 3f [2] 82 22 [2] 80 23 [2] 9b 25 [2] 87 22 [2] 9b 0d }

  condition:
    any of them
}