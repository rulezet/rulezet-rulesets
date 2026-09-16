rule TTP_XOR_MULT_DOSStub_1a57 {
  strings:
    $key_1a57 = { 4e 3f [2] 3a 27 [2] 7d 25 [2] 3a 34 [2] 74 38 [2] 78 32 [2] 6f 39 [2] 74 77 [2] 49 }

  condition:
    any of them
}