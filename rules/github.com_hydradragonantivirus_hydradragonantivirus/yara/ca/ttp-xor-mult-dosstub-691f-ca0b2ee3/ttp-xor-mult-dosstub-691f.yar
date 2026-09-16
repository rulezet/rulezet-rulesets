rule TTP_XOR_MULT_DOSStub_691f {
  strings:
    $key_691f = { 3d 77 [2] 49 6f [2] 0e 6d [2] 49 7c [2] 07 70 [2] 0b 7a [2] 1c 71 [2] 07 3f [2] 3a }

  condition:
    any of them
}