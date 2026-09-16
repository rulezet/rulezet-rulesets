rule TTP_XOR_MULT_DOSStub_19f9 {
  strings:
    $key_19f9 = { 4d 91 [2] 39 89 [2] 7e 8b [2] 39 9a [2] 77 96 [2] 7b 9c [2] 6c 97 [2] 77 d9 [2] 4a }

  condition:
    any of them
}