rule TTP_XOR_MULT_DOSStub_8567 {
  strings:
    $key_8567 = { d1 0f [2] a5 17 [2] e2 15 [2] a5 04 [2] eb 08 [2] e7 02 [2] f0 09 [2] eb 47 [2] d6 }

  condition:
    any of them
}