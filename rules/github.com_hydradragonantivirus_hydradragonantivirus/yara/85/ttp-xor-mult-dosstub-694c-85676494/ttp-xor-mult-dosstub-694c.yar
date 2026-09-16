rule TTP_XOR_MULT_DOSStub_694c {
  strings:
    $key_694c = { 3d 24 [2] 49 3c [2] 0e 3e [2] 49 2f [2] 07 23 [2] 0b 29 [2] 1c 22 [2] 07 6c [2] 3a }

  condition:
    any of them
}