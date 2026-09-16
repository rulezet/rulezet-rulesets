rule TTP_XOR_MULT_DOSStub_2a57 {
  strings:
    $key_2a57 = { 7e 3f [2] 0a 27 [2] 4d 25 [2] 0a 34 [2] 44 38 [2] 48 32 [2] 5f 39 [2] 44 77 [2] 79 }

  condition:
    any of them
}