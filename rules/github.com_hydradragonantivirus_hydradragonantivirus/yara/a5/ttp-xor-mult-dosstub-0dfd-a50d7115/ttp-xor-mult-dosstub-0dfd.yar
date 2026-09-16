rule TTP_XOR_MULT_DOSStub_0dfd {
  strings:
    $key_0dfd = { 59 95 [2] 2d 8d [2] 6a 8f [2] 2d 9e [2] 63 92 [2] 6f 98 [2] 78 93 [2] 63 dd [2] 5e }

  condition:
    any of them
}