rule TTP_XOR_MULT_DOSStub_69f4 {
  strings:
    $key_69f4 = { 3d 9c [2] 49 84 [2] 0e 86 [2] 49 97 [2] 07 9b [2] 0b 91 [2] 1c 9a [2] 07 d4 [2] 3a }

  condition:
    any of them
}