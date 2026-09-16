rule TTP_XOR_MULT_DOSStub_097f {
  strings:
    $key_097f = { 5d 17 [2] 29 0f [2] 6e 0d [2] 29 1c [2] 67 10 [2] 6b 1a [2] 7c 11 [2] 67 5f [2] 5a }

  condition:
    any of them
}