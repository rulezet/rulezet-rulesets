rule TTP_XOR_MULT_DOSStub_0278 {
  strings:
    $key_0278 = { 56 10 [2] 22 08 [2] 65 0a [2] 22 1b [2] 6c 17 [2] 60 1d [2] 77 16 [2] 6c 58 [2] 51 }

  condition:
    any of them
}