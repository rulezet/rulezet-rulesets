rule TTP_XOR_MULT_DOSStub_8a57 {
  strings:
    $key_8a57 = { de 3f [2] aa 27 [2] ed 25 [2] aa 34 [2] e4 38 [2] e8 32 [2] ff 39 [2] e4 77 [2] d9 }

  condition:
    any of them
}