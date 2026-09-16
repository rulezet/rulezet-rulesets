rule TTP_XOR_MULT_DOSStub_19e1 {
  strings:
    $key_19e1 = { 4d 89 [2] 39 91 [2] 7e 93 [2] 39 82 [2] 77 8e [2] 7b 84 [2] 6c 8f [2] 77 c1 [2] 4a }

  condition:
    any of them
}