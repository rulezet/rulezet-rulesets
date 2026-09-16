rule TTP_XOR_MULT_DOSStub_1961 {
  strings:
    $key_1961 = { 4d 09 [2] 39 11 [2] 7e 13 [2] 39 02 [2] 77 0e [2] 7b 04 [2] 6c 0f [2] 77 41 [2] 4a }

  condition:
    any of them
}