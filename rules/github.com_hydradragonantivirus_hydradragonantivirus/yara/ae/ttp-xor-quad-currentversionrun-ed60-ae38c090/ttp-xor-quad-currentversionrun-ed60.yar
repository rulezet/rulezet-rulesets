rule TTP_XOR_QUAD_CurrentVersionRun_ed60 {
  strings:
    $key_ed60 = { be 0f [2] 9a 01 [2] b1 2d [2] 9f 0f [2] 8b 14 [2] 84 0e [2] 9a 13 [2] 98 12 [2] 83 14 [2] 9f 13 [2] 83 3c }

  condition:
    any of them
}