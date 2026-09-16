rule TTP_XOR_QUAD_CurrentVersionRun_ed1e {
  strings:
    $key_ed1e = { be 71 [2] 9a 7f [2] b1 53 [2] 9f 71 [2] 8b 6a [2] 84 70 [2] 9a 6d [2] 98 6c [2] 83 6a [2] 9f 6d [2] 83 42 }

  condition:
    any of them
}