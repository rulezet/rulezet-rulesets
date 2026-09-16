rule TTP_XOR_MULT_DOSStub_406a {
  strings:
    $key_406a = { 14 02 [2] 60 1a [2] 27 18 [2] 60 09 [2] 2e 05 [2] 22 0f [2] 35 04 [2] 2e 4a [2] 13 }

  condition:
    any of them
}