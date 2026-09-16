rule TTP_XOR_MULT_DOSStub_f90e {
  strings:
    $key_f90e = { ad 66 [2] d9 7e [2] 9e 7c [2] d9 6d [2] 97 61 [2] 9b 6b [2] 8c 60 [2] 97 2e [2] aa }

  condition:
    any of them
}