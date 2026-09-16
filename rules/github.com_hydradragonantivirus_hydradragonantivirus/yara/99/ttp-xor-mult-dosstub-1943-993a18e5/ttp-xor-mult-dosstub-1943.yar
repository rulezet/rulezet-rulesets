rule TTP_XOR_MULT_DOSStub_1943 {
  strings:
    $key_1943 = { 4d 2b [2] 39 33 [2] 7e 31 [2] 39 20 [2] 77 2c [2] 7b 26 [2] 6c 2d [2] 77 63 [2] 4a }

  condition:
    any of them
}