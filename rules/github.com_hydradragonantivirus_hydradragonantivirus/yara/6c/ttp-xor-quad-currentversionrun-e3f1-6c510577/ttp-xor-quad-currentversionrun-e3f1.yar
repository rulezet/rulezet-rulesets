rule TTP_XOR_QUAD_CurrentVersionRun_e3f1 {
  strings:
    $key_e3f1 = { b0 9e [2] 94 90 [2] bf bc [2] 91 9e [2] 85 85 [2] 8a 9f [2] 94 82 [2] 96 83 [2] 8d 85 [2] 91 82 [2] 8d ad }

  condition:
    any of them
}