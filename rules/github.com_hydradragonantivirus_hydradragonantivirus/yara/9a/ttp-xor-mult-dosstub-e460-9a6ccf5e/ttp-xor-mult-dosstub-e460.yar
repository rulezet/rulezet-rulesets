rule TTP_XOR_MULT_DOSStub_e460 {
  strings:
    $key_e460 = { b0 08 [2] c4 10 [2] 83 12 [2] c4 03 [2] 8a 0f [2] 86 05 [2] 91 0e [2] 8a 40 [2] b7 }

  condition:
    any of them
}