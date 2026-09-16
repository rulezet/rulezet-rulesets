rule TTP_XOR_QUAD_CurrentVersionRun_2cf1 {
  strings:
    $key_2cf1 = { 7f 9e [2] 5b 90 [2] 70 bc [2] 5e 9e [2] 4a 85 [2] 45 9f [2] 5b 82 [2] 59 83 [2] 42 85 [2] 5e 82 [2] 42 ad }

  condition:
    any of them
}