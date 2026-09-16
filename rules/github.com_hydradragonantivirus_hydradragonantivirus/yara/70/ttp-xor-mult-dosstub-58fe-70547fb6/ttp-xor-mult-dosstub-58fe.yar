rule TTP_XOR_MULT_DOSStub_58fe {
  strings:
    $key_58fe = { 0c 96 [2] 78 8e [2] 3f 8c [2] 78 9d [2] 36 91 [2] 3a 9b [2] 2d 90 [2] 36 de [2] 0b }

  condition:
    any of them
}