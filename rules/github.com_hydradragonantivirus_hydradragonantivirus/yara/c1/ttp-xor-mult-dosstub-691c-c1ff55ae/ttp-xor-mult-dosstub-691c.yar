rule TTP_XOR_MULT_DOSStub_691c {
  strings:
    $key_691c = { 3d 74 [2] 49 6c [2] 0e 6e [2] 49 7f [2] 07 73 [2] 0b 79 [2] 1c 72 [2] 07 3c [2] 3a }

  condition:
    any of them
}