rule TTP_XOR_QUAD_CurrentVersionRun_19f1 {
  strings:
    $key_19f1 = { 4a 9e [2] 6e 90 [2] 45 bc [2] 6b 9e [2] 7f 85 [2] 70 9f [2] 6e 82 [2] 6c 83 [2] 77 85 [2] 6b 82 [2] 77 ad }

  condition:
    any of them
}