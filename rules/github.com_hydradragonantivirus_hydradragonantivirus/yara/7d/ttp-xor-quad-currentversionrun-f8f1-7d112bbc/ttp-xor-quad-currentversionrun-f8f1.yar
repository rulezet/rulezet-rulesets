rule TTP_XOR_QUAD_CurrentVersionRun_f8f1 {
  strings:
    $key_f8f1 = { ab 9e [2] 8f 90 [2] a4 bc [2] 8a 9e [2] 9e 85 [2] 91 9f [2] 8f 82 [2] 8d 83 [2] 96 85 [2] 8a 82 [2] 96 ad }

  condition:
    any of them
}