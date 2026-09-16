rule TTP_XOR_MULT_DOSStub_69f2 {
  strings:
    $key_69f2 = { 3d 9a [2] 49 82 [2] 0e 80 [2] 49 91 [2] 07 9d [2] 0b 97 [2] 1c 9c [2] 07 d2 [2] 3a }

  condition:
    any of them
}