rule TTP_XOR_MULT_DOSStub_706a {
  strings:
    $key_706a = { 24 02 [2] 50 1a [2] 17 18 [2] 50 09 [2] 1e 05 [2] 12 0f [2] 05 04 [2] 1e 4a [2] 23 }

  condition:
    any of them
}