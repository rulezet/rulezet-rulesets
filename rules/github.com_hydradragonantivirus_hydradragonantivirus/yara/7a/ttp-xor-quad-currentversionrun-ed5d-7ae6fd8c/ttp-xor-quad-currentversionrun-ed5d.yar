rule TTP_XOR_QUAD_CurrentVersionRun_ed5d {
  strings:
    $key_ed5d = { be 32 [2] 9a 3c [2] b1 10 [2] 9f 32 [2] 8b 29 [2] 84 33 [2] 9a 2e [2] 98 2f [2] 83 29 [2] 9f 2e [2] 83 01 }

  condition:
    any of them
}