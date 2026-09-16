rule TTP_XOR_QUAD_CurrentVersionRun_edf1 {
  strings:
    $key_edf1 = { be 9e [2] 9a 90 [2] b1 bc [2] 9f 9e [2] 8b 85 [2] 84 9f [2] 9a 82 [2] 98 83 [2] 83 85 [2] 9f 82 [2] 83 ad }

  condition:
    any of them
}