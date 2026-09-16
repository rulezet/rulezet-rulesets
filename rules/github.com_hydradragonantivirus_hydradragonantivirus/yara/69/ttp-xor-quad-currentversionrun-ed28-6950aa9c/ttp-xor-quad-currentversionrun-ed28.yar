rule TTP_XOR_QUAD_CurrentVersionRun_ed28 {
  strings:
    $key_ed28 = { be 47 [2] 9a 49 [2] b1 65 [2] 9f 47 [2] 8b 5c [2] 84 46 [2] 9a 5b [2] 98 5a [2] 83 5c [2] 9f 5b [2] 83 74 }

  condition:
    any of them
}