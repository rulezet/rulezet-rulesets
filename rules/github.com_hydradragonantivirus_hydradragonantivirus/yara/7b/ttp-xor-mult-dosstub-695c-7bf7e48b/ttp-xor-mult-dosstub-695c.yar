rule TTP_XOR_MULT_DOSStub_695c {
  strings:
    $key_695c = { 3d 34 [2] 49 2c [2] 0e 2e [2] 49 3f [2] 07 33 [2] 0b 39 [2] 1c 32 [2] 07 7c [2] 3a }

  condition:
    any of them
}