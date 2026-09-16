rule TTP_XOR_QUAD_CurrentVersionRun_1b33 {
  strings:
    $key_1b33 = { 48 5c [2] 6c 52 [2] 47 7e [2] 69 5c [2] 7d 47 [2] 72 5d [2] 6c 40 [2] 6e 41 [2] 75 47 [2] 69 40 [2] 75 6f }

  condition:
    any of them
}