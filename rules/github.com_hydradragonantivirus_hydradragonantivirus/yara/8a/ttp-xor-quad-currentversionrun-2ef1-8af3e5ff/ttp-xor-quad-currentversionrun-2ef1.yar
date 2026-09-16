rule TTP_XOR_QUAD_CurrentVersionRun_2ef1 {
  strings:
    $key_2ef1 = { 7d 9e [2] 59 90 [2] 72 bc [2] 5c 9e [2] 48 85 [2] 47 9f [2] 59 82 [2] 5b 83 [2] 40 85 [2] 5c 82 [2] 40 ad }

  condition:
    any of them
}