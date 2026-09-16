rule TTP_XOR_MULT_DOSStub_297f {
  strings:
    $key_297f = { 7d 17 [2] 09 0f [2] 4e 0d [2] 09 1c [2] 47 10 [2] 4b 1a [2] 5c 11 [2] 47 5f [2] 7a }

  condition:
    any of them
}