rule TTP_XOR_QUAD_CurrentVersionRun_ed0d {
  strings:
    $key_ed0d = { be 62 [2] 9a 6c [2] b1 40 [2] 9f 62 [2] 8b 79 [2] 84 63 [2] 9a 7e [2] 98 7f [2] 83 79 [2] 9f 7e [2] 83 51 }

  condition:
    any of them
}