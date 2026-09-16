rule TTP_XOR_QUAD_CurrentVersionRun_ace2 {
  strings:
    $key_ace2 = { ff 8d [2] db 83 [2] f0 af [2] de 8d [2] ca 96 [2] c5 8c [2] db 91 [2] d9 90 [2] c2 96 [2] de 91 [2] c2 be }

  condition:
    any of them
}