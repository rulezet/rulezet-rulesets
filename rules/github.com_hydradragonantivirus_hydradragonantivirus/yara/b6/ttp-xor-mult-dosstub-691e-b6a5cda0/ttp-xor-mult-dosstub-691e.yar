rule TTP_XOR_MULT_DOSStub_691e {
  strings:
    $key_691e = { 3d 76 [2] 49 6e [2] 0e 6c [2] 49 7d [2] 07 71 [2] 0b 7b [2] 1c 70 [2] 07 3e [2] 3a }

  condition:
    any of them
}