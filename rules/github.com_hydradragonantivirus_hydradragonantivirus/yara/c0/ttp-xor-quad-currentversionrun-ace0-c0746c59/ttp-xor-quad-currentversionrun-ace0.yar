rule TTP_XOR_QUAD_CurrentVersionRun_ace0 {
  strings:
    $key_ace0 = { ff 8f [2] db 81 [2] f0 ad [2] de 8f [2] ca 94 [2] c5 8e [2] db 93 [2] d9 92 [2] c2 94 [2] de 93 [2] c2 bc }

  condition:
    any of them
}