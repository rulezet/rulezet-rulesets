rule TTP_XOR_QUAD_CurrentVersionRun_ed6c {
  strings:
    $key_ed6c = { be 03 [2] 9a 0d [2] b1 21 [2] 9f 03 [2] 8b 18 [2] 84 02 [2] 9a 1f [2] 98 1e [2] 83 18 [2] 9f 1f [2] 83 30 }

  condition:
    any of them
}