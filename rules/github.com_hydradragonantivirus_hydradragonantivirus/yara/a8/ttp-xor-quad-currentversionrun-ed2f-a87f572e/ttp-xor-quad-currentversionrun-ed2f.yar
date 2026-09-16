rule TTP_XOR_QUAD_CurrentVersionRun_ed2f {
  strings:
    $key_ed2f = { be 40 [2] 9a 4e [2] b1 62 [2] 9f 40 [2] 8b 5b [2] 84 41 [2] 9a 5c [2] 98 5d [2] 83 5b [2] 9f 5c [2] 83 73 }

  condition:
    any of them
}