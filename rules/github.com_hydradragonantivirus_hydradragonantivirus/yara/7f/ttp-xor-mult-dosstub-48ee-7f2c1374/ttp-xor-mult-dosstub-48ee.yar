rule TTP_XOR_MULT_DOSStub_48ee {
  strings:
    $key_48ee = { 1c 86 [2] 68 9e [2] 2f 9c [2] 68 8d [2] 26 81 [2] 2a 8b [2] 3d 80 [2] 26 ce [2] 1b }

  condition:
    any of them
}