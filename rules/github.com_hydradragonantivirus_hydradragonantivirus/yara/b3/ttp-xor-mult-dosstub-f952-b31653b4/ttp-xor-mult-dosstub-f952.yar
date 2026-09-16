rule TTP_XOR_MULT_DOSStub_f952 {
  strings:
    $key_f952 = { ad 3a [2] d9 22 [2] 9e 20 [2] d9 31 [2] 97 3d [2] 9b 37 [2] 8c 3c [2] 97 72 [2] aa }

  condition:
    any of them
}