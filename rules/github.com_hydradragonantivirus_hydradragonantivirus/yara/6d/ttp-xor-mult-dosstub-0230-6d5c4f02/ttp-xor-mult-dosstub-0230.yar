rule TTP_XOR_MULT_DOSStub_0230 {
  strings:
    $key_0230 = { 56 58 [2] 22 40 [2] 65 42 [2] 22 53 [2] 6c 5f [2] 60 55 [2] 77 5e [2] 6c 10 [2] 51 }

  condition:
    any of them
}