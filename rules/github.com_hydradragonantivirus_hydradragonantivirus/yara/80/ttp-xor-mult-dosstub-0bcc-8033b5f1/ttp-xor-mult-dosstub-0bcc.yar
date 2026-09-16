rule TTP_XOR_MULT_DOSStub_0bcc {
  strings:
    $key_0bcc = { 5f a4 [2] 2b bc [2] 6c be [2] 2b af [2] 65 a3 [2] 69 a9 [2] 7e a2 [2] 65 ec [2] 58 }

  condition:
    any of them
}