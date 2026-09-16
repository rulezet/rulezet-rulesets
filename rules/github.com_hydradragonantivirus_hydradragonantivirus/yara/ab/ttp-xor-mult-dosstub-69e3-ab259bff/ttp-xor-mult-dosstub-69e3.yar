rule TTP_XOR_MULT_DOSStub_69e3 {
  strings:
    $key_69e3 = { 3d 8b [2] 49 93 [2] 0e 91 [2] 49 80 [2] 07 8c [2] 0b 86 [2] 1c 8d [2] 07 c3 [2] 3a }

  condition:
    any of them
}