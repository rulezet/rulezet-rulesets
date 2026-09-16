rule TTP_XOR_QUAD_CurrentVersionRun_e6f1 {
  strings:
    $key_e6f1 = { b5 9e [2] 91 90 [2] ba bc [2] 94 9e [2] 80 85 [2] 8f 9f [2] 91 82 [2] 93 83 [2] 88 85 [2] 94 82 [2] 88 ad }

  condition:
    any of them
}