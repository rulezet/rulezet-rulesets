rule TTP_XOR_MULT_DOSStub_f90b {
  strings:
    $key_f90b = { ad 63 [2] d9 7b [2] 9e 79 [2] d9 68 [2] 97 64 [2] 9b 6e [2] 8c 65 [2] 97 2b [2] aa }

  condition:
    any of them
}