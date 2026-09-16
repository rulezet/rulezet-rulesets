rule TTP_XOR_QUAD_CurrentVersionRun_ec40 {
  strings:
    $key_ec40 = { bf 2f [2] 9b 21 [2] b0 0d [2] 9e 2f [2] 8a 34 [2] 85 2e [2] 9b 33 [2] 99 32 [2] 82 34 [2] 9e 33 [2] 82 1c }

  condition:
    any of them
}