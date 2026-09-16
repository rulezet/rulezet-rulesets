rule TTP_XOR_QUAD_CurrentVersionRun_15f1 {
  strings:
    $key_15f1 = { 46 9e [2] 62 90 [2] 49 bc [2] 67 9e [2] 73 85 [2] 7c 9f [2] 62 82 [2] 60 83 [2] 7b 85 [2] 67 82 [2] 7b ad }

  condition:
    any of them
}