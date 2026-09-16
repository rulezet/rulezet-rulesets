rule TTP_XOR_QUAD_CurrentVersionRun_ed08 {
  strings:
    $key_ed08 = { be 67 [2] 9a 69 [2] b1 45 [2] 9f 67 [2] 8b 7c [2] 84 66 [2] 9a 7b [2] 98 7a [2] 83 7c [2] 9f 7b [2] 83 54 }

  condition:
    any of them
}