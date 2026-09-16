rule TTP_XOR_QUAD_CurrentVersionRun_3df1 {
  strings:
    $key_3df1 = { 6e 9e [2] 4a 90 [2] 61 bc [2] 4f 9e [2] 5b 85 [2] 54 9f [2] 4a 82 [2] 48 83 [2] 53 85 [2] 4f 82 [2] 53 ad }

  condition:
    any of them
}