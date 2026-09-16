rule TTP_XOR_QUAD_CurrentVersionRun_ed76 {
  strings:
    $key_ed76 = { be 19 [2] 9a 17 [2] b1 3b [2] 9f 19 [2] 8b 02 [2] 84 18 [2] 9a 05 [2] 98 04 [2] 83 02 [2] 9f 05 [2] 83 2a }

  condition:
    any of them
}