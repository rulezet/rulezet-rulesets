rule TTP_XOR_QUAD_CurrentVersionRun_ed05 {
  strings:
    $key_ed05 = { be 6a [2] 9a 64 [2] b1 48 [2] 9f 6a [2] 8b 71 [2] 84 6b [2] 9a 76 [2] 98 77 [2] 83 71 [2] 9f 76 [2] 83 59 }

  condition:
    any of them
}