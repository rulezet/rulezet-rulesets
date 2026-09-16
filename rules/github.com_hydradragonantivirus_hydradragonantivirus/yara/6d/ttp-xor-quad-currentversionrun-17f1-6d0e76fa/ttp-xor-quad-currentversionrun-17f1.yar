rule TTP_XOR_QUAD_CurrentVersionRun_17f1 {
  strings:
    $key_17f1 = { 44 9e [2] 60 90 [2] 4b bc [2] 65 9e [2] 71 85 [2] 7e 9f [2] 60 82 [2] 62 83 [2] 79 85 [2] 65 82 [2] 79 ad }

  condition:
    any of them
}