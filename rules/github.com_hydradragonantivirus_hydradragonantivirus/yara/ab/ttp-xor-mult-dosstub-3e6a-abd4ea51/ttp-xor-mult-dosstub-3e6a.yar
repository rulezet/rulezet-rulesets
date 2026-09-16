rule TTP_XOR_MULT_DOSStub_3e6a {
  strings:
    $key_3e6a = { 6a 02 [2] 1e 1a [2] 59 18 [2] 1e 09 [2] 50 05 [2] 5c 0f [2] 4b 04 [2] 50 4a [2] 6d }

  condition:
    any of them
}