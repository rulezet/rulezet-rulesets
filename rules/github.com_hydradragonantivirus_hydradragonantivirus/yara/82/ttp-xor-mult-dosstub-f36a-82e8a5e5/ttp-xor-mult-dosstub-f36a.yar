rule TTP_XOR_MULT_DOSStub_f36a {
  strings:
    $key_f36a = { a7 02 [2] d3 1a [2] 94 18 [2] d3 09 [2] 9d 05 [2] 91 0f [2] 86 04 [2] 9d 4a [2] a0 }

  condition:
    any of them
}