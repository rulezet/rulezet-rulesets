rule TTP_XOR_MULT_DOSStub_f958 {
  strings:
    $key_f958 = { ad 30 [2] d9 28 [2] 9e 2a [2] d9 3b [2] 97 37 [2] 9b 3d [2] 8c 36 [2] 97 78 [2] aa }

  condition:
    any of them
}