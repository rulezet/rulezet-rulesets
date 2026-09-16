rule TTP_XOR_MULT_DOSStub_191d {
  strings:
    $key_191d = { 4d 75 [2] 39 6d [2] 7e 6f [2] 39 7e [2] 77 72 [2] 7b 78 [2] 6c 73 [2] 77 3d [2] 4a }

  condition:
    any of them
}