rule TTP_XOR_MULT_DOSStub_691d {
  strings:
    $key_691d = { 3d 75 [2] 49 6d [2] 0e 6f [2] 49 7e [2] 07 72 [2] 0b 78 [2] 1c 73 [2] 07 3d [2] 3a }

  condition:
    any of them
}