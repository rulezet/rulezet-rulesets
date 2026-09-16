rule TTP_XOR_MULT_DOSStub_fafd {
  strings:
    $key_fafd = { ae 95 [2] da 8d [2] 9d 8f [2] da 9e [2] 94 92 [2] 98 98 [2] 8f 93 [2] 94 dd [2] a9 }

  condition:
    any of them
}