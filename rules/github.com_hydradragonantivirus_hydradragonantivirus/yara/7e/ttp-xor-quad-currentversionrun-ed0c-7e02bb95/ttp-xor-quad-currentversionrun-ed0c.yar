rule TTP_XOR_QUAD_CurrentVersionRun_ed0c {
  strings:
    $key_ed0c = { be 63 [2] 9a 6d [2] b1 41 [2] 9f 63 [2] 8b 78 [2] 84 62 [2] 9a 7f [2] 98 7e [2] 83 78 [2] 9f 7f [2] 83 50 }

  condition:
    any of them
}