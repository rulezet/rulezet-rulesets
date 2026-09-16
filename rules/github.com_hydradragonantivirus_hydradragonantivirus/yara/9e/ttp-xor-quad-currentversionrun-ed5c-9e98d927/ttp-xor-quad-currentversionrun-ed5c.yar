rule TTP_XOR_QUAD_CurrentVersionRun_ed5c {
  strings:
    $key_ed5c = { be 33 [2] 9a 3d [2] b1 11 [2] 9f 33 [2] 8b 28 [2] 84 32 [2] 9a 2f [2] 98 2e [2] 83 28 [2] 9f 2f [2] 83 00 }

  condition:
    any of them
}