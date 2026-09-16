rule TTP_XOR_MULT_DOSStub_694d {
  strings:
    $key_694d = { 3d 25 [2] 49 3d [2] 0e 3f [2] 49 2e [2] 07 22 [2] 0b 28 [2] 1c 23 [2] 07 6d [2] 3a }

  condition:
    any of them
}