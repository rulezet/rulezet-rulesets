rule TTP_XOR_MULT_DOSStub_253f {
  strings:
    $key_253f = { 71 57 [2] 05 4f [2] 42 4d [2] 05 5c [2] 4b 50 [2] 47 5a [2] 50 51 [2] 4b 1f [2] 76 }

  condition:
    any of them
}