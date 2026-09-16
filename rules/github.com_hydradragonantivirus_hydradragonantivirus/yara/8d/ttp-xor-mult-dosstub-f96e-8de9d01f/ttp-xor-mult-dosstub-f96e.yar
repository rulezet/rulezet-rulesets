rule TTP_XOR_MULT_DOSStub_f96e {
  strings:
    $key_f96e = { ad 06 [2] d9 1e [2] 9e 1c [2] d9 0d [2] 97 01 [2] 9b 0b [2] 8c 00 [2] 97 4e [2] aa }

  condition:
    any of them
}