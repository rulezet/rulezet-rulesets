rule TTP_XOR_MULT_DOSStub_19f2 {
  strings:
    $key_19f2 = { 4d 9a [2] 39 82 [2] 7e 80 [2] 39 91 [2] 77 9d [2] 7b 97 [2] 6c 9c [2] 77 d2 [2] 4a }

  condition:
    any of them
}