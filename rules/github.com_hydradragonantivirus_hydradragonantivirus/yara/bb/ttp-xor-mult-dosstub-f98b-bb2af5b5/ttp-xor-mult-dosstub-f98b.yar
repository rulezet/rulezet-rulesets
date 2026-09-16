rule TTP_XOR_MULT_DOSStub_f98b {
  strings:
    $key_f98b = { ad e3 [2] d9 fb [2] 9e f9 [2] d9 e8 [2] 97 e4 [2] 9b ee [2] 8c e5 [2] 97 ab [2] aa }

  condition:
    any of them
}