rule TTP_XOR_MULT_DOSStub_6b7f {
  strings:
    $key_6b7f = { 3f 17 [2] 4b 0f [2] 0c 0d [2] 4b 1c [2] 05 10 [2] 09 1a [2] 1e 11 [2] 05 5f [2] 38 }

  condition:
    any of them
}