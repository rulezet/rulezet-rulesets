rule TTP_XOR_MULT_DOSStub_6964 {
  strings:
    $key_6964 = { 3d 0c [2] 49 14 [2] 0e 16 [2] 49 07 [2] 07 0b [2] 0b 01 [2] 1c 0a [2] 07 44 [2] 3a }

  condition:
    any of them
}