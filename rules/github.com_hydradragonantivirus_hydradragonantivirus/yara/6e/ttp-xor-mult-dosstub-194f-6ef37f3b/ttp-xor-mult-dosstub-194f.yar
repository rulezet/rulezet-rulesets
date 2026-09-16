rule TTP_XOR_MULT_DOSStub_194f {
  strings:
    $key_194f = { 4d 27 [2] 39 3f [2] 7e 3d [2] 39 2c [2] 77 20 [2] 7b 2a [2] 6c 21 [2] 77 6f [2] 4a }

  condition:
    any of them
}