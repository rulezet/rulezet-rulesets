rule TTP_XOR_QUAD_CurrentVersionRun_ed1f {
  strings:
    $key_ed1f = { be 70 [2] 9a 7e [2] b1 52 [2] 9f 70 [2] 8b 6b [2] 84 71 [2] 9a 6c [2] 98 6d [2] 83 6b [2] 9f 6c [2] 83 43 }

  condition:
    any of them
}