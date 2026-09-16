rule TTP_XOR_MULT_DOSStub_39e3 {
  strings:
    $key_39e3 = { 6d 8b [2] 19 93 [2] 5e 91 [2] 19 80 [2] 57 8c [2] 5b 86 [2] 4c 8d [2] 57 c3 [2] 6a }

  condition:
    any of them
}