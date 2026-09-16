rule TTP_XOR_MULT_DOSStub_69ee {
  strings:
    $key_69ee = { 3d 86 [2] 49 9e [2] 0e 9c [2] 49 8d [2] 07 81 [2] 0b 8b [2] 1c 80 [2] 07 ce [2] 3a }

  condition:
    any of them
}