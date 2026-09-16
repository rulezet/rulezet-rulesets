rule TTP_XOR_QUAD_CurrentVersionRun_7ef1 {
  strings:
    $key_7ef1 = { 2d 9e [2] 09 90 [2] 22 bc [2] 0c 9e [2] 18 85 [2] 17 9f [2] 09 82 [2] 0b 83 [2] 10 85 [2] 0c 82 [2] 10 ad }

  condition:
    any of them
}