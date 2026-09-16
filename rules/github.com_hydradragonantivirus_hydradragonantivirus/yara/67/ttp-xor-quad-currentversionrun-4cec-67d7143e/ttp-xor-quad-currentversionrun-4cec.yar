rule TTP_XOR_QUAD_CurrentVersionRun_4cec {
  strings:
    $key_4cec = { 1f 83 [2] 3b 8d [2] 10 a1 [2] 3e 83 [2] 2a 98 [2] 25 82 [2] 3b 9f [2] 39 9e [2] 22 98 [2] 3e 9f [2] 22 b0 }

  condition:
    any of them
}