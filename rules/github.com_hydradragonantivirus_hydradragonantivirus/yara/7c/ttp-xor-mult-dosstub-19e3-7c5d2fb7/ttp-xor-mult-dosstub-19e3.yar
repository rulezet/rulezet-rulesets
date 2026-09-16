rule TTP_XOR_MULT_DOSStub_19e3 {
  strings:
    $key_19e3 = { 4d 8b [2] 39 93 [2] 7e 91 [2] 39 80 [2] 77 8c [2] 7b 86 [2] 6c 8d [2] 77 c3 [2] 4a }

  condition:
    any of them
}