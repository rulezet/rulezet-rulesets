rule TTP_XOR_MULT_DOSStub_f98c {
  strings:
    $key_f98c = { ad e4 [2] d9 fc [2] 9e fe [2] d9 ef [2] 97 e3 [2] 9b e9 [2] 8c e2 [2] 97 ac [2] aa }

  condition:
    any of them
}