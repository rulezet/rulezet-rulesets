rule TTP_XOR_MULT_DOSStub_1952 {
  strings:
    $key_1952 = { 4d 3a [2] 39 22 [2] 7e 20 [2] 39 31 [2] 77 3d [2] 7b 37 [2] 6c 3c [2] 77 72 [2] 4a }

  condition:
    any of them
}