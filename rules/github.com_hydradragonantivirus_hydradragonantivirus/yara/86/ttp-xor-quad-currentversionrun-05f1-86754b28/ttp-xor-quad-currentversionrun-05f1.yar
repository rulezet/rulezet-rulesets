rule TTP_XOR_QUAD_CurrentVersionRun_05f1 {
  strings:
    $key_05f1 = { 56 9e [2] 72 90 [2] 59 bc [2] 77 9e [2] 63 85 [2] 6c 9f [2] 72 82 [2] 70 83 [2] 6b 85 [2] 77 82 [2] 6b ad }

  condition:
    any of them
}