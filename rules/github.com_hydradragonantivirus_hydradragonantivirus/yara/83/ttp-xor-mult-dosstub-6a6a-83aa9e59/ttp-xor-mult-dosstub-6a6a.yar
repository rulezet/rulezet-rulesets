rule TTP_XOR_MULT_DOSStub_6a6a {
  strings:
    $key_6a6a = { 3e 02 [2] 4a 1a [2] 0d 18 [2] 4a 09 [2] 04 05 [2] 08 0f [2] 1f 04 [2] 04 4a [2] 39 }

  condition:
    any of them
}