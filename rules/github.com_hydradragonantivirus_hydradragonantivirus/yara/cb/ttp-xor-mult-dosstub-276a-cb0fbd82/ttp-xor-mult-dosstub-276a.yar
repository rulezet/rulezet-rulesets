rule TTP_XOR_MULT_DOSStub_276a {
  strings:
    $key_276a = { 73 02 [2] 07 1a [2] 40 18 [2] 07 09 [2] 49 05 [2] 45 0f [2] 52 04 [2] 49 4a [2] 74 }

  condition:
    any of them
}