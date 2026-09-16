rule TTP_XOR_MULT_DOSStub_8abe {
  strings:
    $key_8abe = { de d6 [2] aa ce [2] ed cc [2] aa dd [2] e4 d1 [2] e8 db [2] ff d0 [2] e4 9e [2] d9 }

  condition:
    any of them
}