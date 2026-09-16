rule TTP_XOR_QUAD_CurrentVersionRun_ed40 {
  strings:
    $key_ed40 = { be 2f [2] 9a 21 [2] b1 0d [2] 9f 2f [2] 8b 34 [2] 84 2e [2] 9a 33 [2] 98 32 [2] 83 34 [2] 9f 33 [2] 83 1c }

  condition:
    any of them
}