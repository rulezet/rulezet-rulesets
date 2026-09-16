rule TTP_XOR_MULT_DOSStub_3dfd {
  strings:
    $key_3dfd = { 69 95 [2] 1d 8d [2] 5a 8f [2] 1d 9e [2] 53 92 [2] 5f 98 [2] 48 93 [2] 53 dd [2] 6e }

  condition:
    any of them
}