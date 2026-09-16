rule TTP_XOR_MULT_DOSStub_376a {
  strings:
    $key_376a = { 63 02 [2] 17 1a [2] 50 18 [2] 17 09 [2] 59 05 [2] 55 0f [2] 42 04 [2] 59 4a [2] 64 }

  condition:
    any of them
}