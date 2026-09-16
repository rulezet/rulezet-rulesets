rule TTP_XOR_MULT_DOSStub_502a {
  strings:
    $key_502a = { 04 42 [2] 70 5a [2] 37 58 [2] 70 49 [2] 3e 45 [2] 32 4f [2] 25 44 [2] 3e 0a [2] 03 }

  condition:
    any of them
}