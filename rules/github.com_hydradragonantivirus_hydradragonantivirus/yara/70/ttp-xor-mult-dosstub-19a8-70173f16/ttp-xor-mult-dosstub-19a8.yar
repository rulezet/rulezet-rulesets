rule TTP_XOR_MULT_DOSStub_19a8 {
  strings:
    $key_19a8 = { 4d c0 [2] 39 d8 [2] 7e da [2] 39 cb [2] 77 c7 [2] 7b cd [2] 6c c6 [2] 77 88 [2] 4a }

  condition:
    any of them
}