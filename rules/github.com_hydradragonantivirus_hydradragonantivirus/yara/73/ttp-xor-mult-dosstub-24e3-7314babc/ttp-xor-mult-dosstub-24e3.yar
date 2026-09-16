rule TTP_XOR_MULT_DOSStub_24e3 {
  strings:
    $key_24e3 = { 70 8b [2] 04 93 [2] 43 91 [2] 04 80 [2] 4a 8c [2] 46 86 [2] 51 8d [2] 4a c3 [2] 77 }

  condition:
    any of them
}