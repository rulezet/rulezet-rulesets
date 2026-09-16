rule TTP_XOR_MULT_DOSStub_19ad {
  strings:
    $key_19ad = { 4d c5 [2] 39 dd [2] 7e df [2] 39 ce [2] 77 c2 [2] 7b c8 [2] 6c c3 [2] 77 8d [2] 4a }

  condition:
    any of them
}