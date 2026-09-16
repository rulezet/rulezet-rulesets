rule TTP_XOR_MULT_DOSStub_58fd {
  strings:
    $key_58fd = { 0c 95 [2] 78 8d [2] 3f 8f [2] 78 9e [2] 36 92 [2] 3a 98 [2] 2d 93 [2] 36 dd [2] 0b }

  condition:
    any of them
}