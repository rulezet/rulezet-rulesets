rule TTP_XOR_MULT_DOSStub_19a2 {
  strings:
    $key_19a2 = { 4d ca [2] 39 d2 [2] 7e d0 [2] 39 c1 [2] 77 cd [2] 7b c7 [2] 6c cc [2] 77 82 [2] 4a }

  condition:
    any of them
}