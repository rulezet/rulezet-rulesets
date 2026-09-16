rule TTP_XOR_QUAD_CurrentVersionRun_4901 {
  strings:
    $key_4901 = { 1a 6e [2] 3e 60 [2] 15 4c [2] 3b 6e [2] 2f 75 [2] 20 6f [2] 3e 72 [2] 3c 73 [2] 27 75 [2] 3b 72 [2] 27 5d }

  condition:
    any of them
}