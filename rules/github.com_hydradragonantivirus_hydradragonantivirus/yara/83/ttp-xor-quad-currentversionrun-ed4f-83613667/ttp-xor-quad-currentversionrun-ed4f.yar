rule TTP_XOR_QUAD_CurrentVersionRun_ed4f {
  strings:
    $key_ed4f = { be 20 [2] 9a 2e [2] b1 02 [2] 9f 20 [2] 8b 3b [2] 84 21 [2] 9a 3c [2] 98 3d [2] 83 3b [2] 9f 3c [2] 83 13 }

  condition:
    any of them
}