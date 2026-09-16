rule TTP_XOR_QUAD_CurrentVersionRun_ac02 {
  strings:
    $key_ac02 = { ff 6d [2] db 63 [2] f0 4f [2] de 6d [2] ca 76 [2] c5 6c [2] db 71 [2] d9 70 [2] c2 76 [2] de 71 [2] c2 5e }

  condition:
    any of them
}