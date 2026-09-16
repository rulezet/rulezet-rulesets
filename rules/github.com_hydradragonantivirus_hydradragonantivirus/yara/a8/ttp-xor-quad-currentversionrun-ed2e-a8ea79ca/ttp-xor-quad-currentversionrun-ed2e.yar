rule TTP_XOR_QUAD_CurrentVersionRun_ed2e {
  strings:
    $key_ed2e = { be 41 [2] 9a 4f [2] b1 63 [2] 9f 41 [2] 8b 5a [2] 84 40 [2] 9a 5d [2] 98 5c [2] 83 5a [2] 9f 5d [2] 83 72 }

  condition:
    any of them
}