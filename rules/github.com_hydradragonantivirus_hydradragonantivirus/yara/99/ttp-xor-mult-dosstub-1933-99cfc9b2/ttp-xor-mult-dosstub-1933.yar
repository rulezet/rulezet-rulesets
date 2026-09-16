rule TTP_XOR_MULT_DOSStub_1933 {
  strings:
    $key_1933 = { 4d 5b [2] 39 43 [2] 7e 41 [2] 39 50 [2] 77 5c [2] 7b 56 [2] 6c 5d [2] 77 13 [2] 4a }

  condition:
    any of them
}