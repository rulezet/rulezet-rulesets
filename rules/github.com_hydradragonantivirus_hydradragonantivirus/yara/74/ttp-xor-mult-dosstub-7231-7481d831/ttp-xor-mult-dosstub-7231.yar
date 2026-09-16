rule TTP_XOR_MULT_DOSStub_7231 {
  strings:
    $key_7231 = { 26 59 [2] 52 41 [2] 15 43 [2] 52 52 [2] 1c 5e [2] 10 54 [2] 07 5f [2] 1c 11 [2] 21 }

  condition:
    any of them
}