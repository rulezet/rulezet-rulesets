rule TTP_XOR_MULT_DOSStub_f98a {
  strings:
    $key_f98a = { ad e2 [2] d9 fa [2] 9e f8 [2] d9 e9 [2] 97 e5 [2] 9b ef [2] 8c e4 [2] 97 aa [2] aa }

  condition:
    any of them
}