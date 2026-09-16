rule TTP_XOR_MULT_DOSStub_f925 {
  strings:
    $key_f925 = { ad 4d [2] d9 55 [2] 9e 57 [2] d9 46 [2] 97 4a [2] 9b 40 [2] 8c 4b [2] 97 05 [2] aa }

  condition:
    any of them
}