rule TTP_XOR_QUAD_CurrentVersionRun_6cf1 {
  strings:
    $key_6cf1 = { 3f 9e [2] 1b 90 [2] 30 bc [2] 1e 9e [2] 0a 85 [2] 05 9f [2] 1b 82 [2] 19 83 [2] 02 85 [2] 1e 82 [2] 02 ad }

  condition:
    any of them
}