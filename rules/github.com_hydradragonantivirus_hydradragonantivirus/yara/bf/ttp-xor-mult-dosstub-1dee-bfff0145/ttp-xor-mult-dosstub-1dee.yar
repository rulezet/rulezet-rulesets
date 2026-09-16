rule TTP_XOR_MULT_DOSStub_1dee {
  strings:
    $key_1dee = { 49 86 [2] 3d 9e [2] 7a 9c [2] 3d 8d [2] 73 81 [2] 7f 8b [2] 68 80 [2] 73 ce [2] 4e }

  condition:
    any of them
}