rule TTP_XOR_QUAD_CurrentVersionRun_49f1 {
  strings:
    $key_49f1 = { 1a 9e [2] 3e 90 [2] 15 bc [2] 3b 9e [2] 2f 85 [2] 20 9f [2] 3e 82 [2] 3c 83 [2] 27 85 [2] 3b 82 [2] 27 ad }

  condition:
    any of them
}