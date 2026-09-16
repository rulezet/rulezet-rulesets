rule TTP_XOR_QUAD_CurrentVersionRun_ed2c {
  strings:
    $key_ed2c = { be 43 [2] 9a 4d [2] b1 61 [2] 9f 43 [2] 8b 58 [2] 84 42 [2] 9a 5f [2] 98 5e [2] 83 58 [2] 9f 5f [2] 83 70 }

  condition:
    any of them
}