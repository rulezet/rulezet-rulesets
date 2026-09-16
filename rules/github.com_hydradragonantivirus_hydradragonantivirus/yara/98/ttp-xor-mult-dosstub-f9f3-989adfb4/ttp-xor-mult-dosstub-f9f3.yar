rule TTP_XOR_MULT_DOSStub_f9f3 {
  strings:
    $key_f9f3 = { ad 9b [2] d9 83 [2] 9e 81 [2] d9 90 [2] 97 9c [2] 9b 96 [2] 8c 9d [2] 97 d3 [2] aa }

  condition:
    any of them
}