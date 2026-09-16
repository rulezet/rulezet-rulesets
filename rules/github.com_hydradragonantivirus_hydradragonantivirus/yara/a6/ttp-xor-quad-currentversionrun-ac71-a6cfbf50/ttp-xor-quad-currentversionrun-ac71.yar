rule TTP_XOR_QUAD_CurrentVersionRun_ac71 {
  strings:
    $key_ac71 = { ff 1e [2] db 10 [2] f0 3c [2] de 1e [2] ca 05 [2] c5 1f [2] db 02 [2] d9 03 [2] c2 05 [2] de 02 [2] c2 2d }

  condition:
    any of them
}