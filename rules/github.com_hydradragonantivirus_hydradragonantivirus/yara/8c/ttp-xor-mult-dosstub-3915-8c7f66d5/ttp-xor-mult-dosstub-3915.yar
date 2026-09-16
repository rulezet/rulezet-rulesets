rule TTP_XOR_MULT_DOSStub_3915 {
  strings:
    $key_3915 = { 6d 7d [2] 19 65 [2] 5e 67 [2] 19 76 [2] 57 7a [2] 5b 70 [2] 4c 7b [2] 57 35 [2] 6a }

  condition:
    any of them
}