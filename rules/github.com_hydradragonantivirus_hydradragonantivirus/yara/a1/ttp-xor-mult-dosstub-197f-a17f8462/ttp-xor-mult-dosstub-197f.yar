rule TTP_XOR_MULT_DOSStub_197f {
  strings:
    $key_197f = { 4d 17 [2] 39 0f [2] 7e 0d [2] 39 1c [2] 77 10 [2] 7b 1a [2] 6c 11 [2] 77 5f [2] 4a }

  condition:
    any of them
}