rule TTP_XOR_MULT_DOSStub_1922 {
  strings:
    $key_1922 = { 4d 4a [2] 39 52 [2] 7e 50 [2] 39 41 [2] 77 4d [2] 7b 47 [2] 6c 4c [2] 77 02 [2] 4a }

  condition:
    any of them
}