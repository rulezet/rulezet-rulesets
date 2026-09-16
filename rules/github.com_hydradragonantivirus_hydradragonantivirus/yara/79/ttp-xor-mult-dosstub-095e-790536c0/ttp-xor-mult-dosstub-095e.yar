rule TTP_XOR_MULT_DOSStub_095e {
  strings:
    $key_095e = { 5d 36 [2] 29 2e [2] 6e 2c [2] 29 3d [2] 67 31 [2] 6b 3b [2] 7c 30 [2] 67 7e [2] 5a }

  condition:
    any of them
}