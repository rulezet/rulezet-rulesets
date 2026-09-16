rule TTP_XOR_QUAD_CurrentVersionRun_2bf1 {
  strings:
    $key_2bf1 = { 78 9e [2] 5c 90 [2] 77 bc [2] 59 9e [2] 4d 85 [2] 42 9f [2] 5c 82 [2] 5e 83 [2] 45 85 [2] 59 82 [2] 45 ad }

  condition:
    any of them
}