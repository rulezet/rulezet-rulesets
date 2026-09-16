rule TTP_XOR_QUAD_CurrentVersionRun_a2fa {
  strings:
    $key_a2fa = { f1 95 [2] d5 9b [2] fe b7 [2] d0 95 [2] c4 8e [2] cb 94 [2] d5 89 [2] d7 88 [2] cc 8e [2] d0 89 [2] cc a6 }

  condition:
    any of them
}