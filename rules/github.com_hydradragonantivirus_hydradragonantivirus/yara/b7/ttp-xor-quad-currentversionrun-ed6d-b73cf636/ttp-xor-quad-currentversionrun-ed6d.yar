rule TTP_XOR_QUAD_CurrentVersionRun_ed6d {
  strings:
    $key_ed6d = { be 02 [2] 9a 0c [2] b1 20 [2] 9f 02 [2] 8b 19 [2] 84 03 [2] 9a 1e [2] 98 1f [2] 83 19 [2] 9f 1e [2] 83 31 }

  condition:
    any of them
}