rule TTP_XOR_QUAD_CurrentVersionRun_ed24 {
  strings:
    $key_ed24 = { be 4b [2] 9a 45 [2] b1 69 [2] 9f 4b [2] 8b 50 [2] 84 4a [2] 9a 57 [2] 98 56 [2] 83 50 [2] 9f 57 [2] 83 78 }

  condition:
    any of them
}