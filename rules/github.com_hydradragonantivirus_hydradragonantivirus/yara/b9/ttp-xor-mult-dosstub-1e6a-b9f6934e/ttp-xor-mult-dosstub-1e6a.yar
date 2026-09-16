rule TTP_XOR_MULT_DOSStub_1e6a {
  strings:
    $key_1e6a = { 4a 02 [2] 3e 1a [2] 79 18 [2] 3e 09 [2] 70 05 [2] 7c 0f [2] 6b 04 [2] 70 4a [2] 4d }

  condition:
    any of them
}