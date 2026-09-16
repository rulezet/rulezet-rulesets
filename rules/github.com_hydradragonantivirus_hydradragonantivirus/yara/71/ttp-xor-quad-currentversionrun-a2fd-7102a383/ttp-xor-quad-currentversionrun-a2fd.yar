rule TTP_XOR_QUAD_CurrentVersionRun_a2fd {
  strings:
    $key_a2fd = { f1 92 [2] d5 9c [2] fe b0 [2] d0 92 [2] c4 89 [2] cb 93 [2] d5 8e [2] d7 8f [2] cc 89 [2] d0 8e [2] cc a1 }

  condition:
    any of them
}