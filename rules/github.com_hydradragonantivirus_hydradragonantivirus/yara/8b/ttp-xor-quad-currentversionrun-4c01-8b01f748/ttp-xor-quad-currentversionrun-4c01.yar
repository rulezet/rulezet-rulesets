rule TTP_XOR_QUAD_CurrentVersionRun_4c01 {
  strings:
    $key_4c01 = { 1f 6e [2] 3b 60 [2] 10 4c [2] 3e 6e [2] 2a 75 [2] 25 6f [2] 3b 72 [2] 39 73 [2] 22 75 [2] 3e 72 [2] 22 5d }

  condition:
    any of them
}