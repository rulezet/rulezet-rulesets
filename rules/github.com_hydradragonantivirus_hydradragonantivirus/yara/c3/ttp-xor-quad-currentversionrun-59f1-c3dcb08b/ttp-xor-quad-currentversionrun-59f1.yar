rule TTP_XOR_QUAD_CurrentVersionRun_59f1 {
  strings:
    $key_59f1 = { 0a 9e [2] 2e 90 [2] 05 bc [2] 2b 9e [2] 3f 85 [2] 30 9f [2] 2e 82 [2] 2c 83 [2] 37 85 [2] 2b 82 [2] 37 ad }

  condition:
    any of them
}