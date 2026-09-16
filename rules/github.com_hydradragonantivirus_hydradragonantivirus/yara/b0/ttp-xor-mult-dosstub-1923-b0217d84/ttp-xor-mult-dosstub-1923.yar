rule TTP_XOR_MULT_DOSStub_1923 {
  strings:
    $key_1923 = { 4d 4b [2] 39 53 [2] 7e 51 [2] 39 40 [2] 77 4c [2] 7b 46 [2] 6c 4d [2] 77 03 [2] 4a }

  condition:
    any of them
}