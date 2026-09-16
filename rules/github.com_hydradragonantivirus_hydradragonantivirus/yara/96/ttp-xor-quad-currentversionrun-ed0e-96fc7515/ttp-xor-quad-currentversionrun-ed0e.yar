rule TTP_XOR_QUAD_CurrentVersionRun_ed0e {
  strings:
    $key_ed0e = { be 61 [2] 9a 6f [2] b1 43 [2] 9f 61 [2] 8b 7a [2] 84 60 [2] 9a 7d [2] 98 7c [2] 83 7a [2] 9f 7d [2] 83 52 }

  condition:
    any of them
}