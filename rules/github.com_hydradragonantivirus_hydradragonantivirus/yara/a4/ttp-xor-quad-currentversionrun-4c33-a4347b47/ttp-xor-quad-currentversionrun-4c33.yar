rule TTP_XOR_QUAD_CurrentVersionRun_4c33 {
  strings:
    $key_4c33 = { 1f 5c [2] 3b 52 [2] 10 7e [2] 3e 5c [2] 2a 47 [2] 25 5d [2] 3b 40 [2] 39 41 [2] 22 47 [2] 3e 40 [2] 22 6f }

  condition:
    any of them
}