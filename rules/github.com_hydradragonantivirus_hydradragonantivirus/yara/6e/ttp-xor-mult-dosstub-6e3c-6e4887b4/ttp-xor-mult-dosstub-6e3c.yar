rule TTP_XOR_MULT_DOSStub_6e3c {
  strings:
    $key_6e3c = { 3a 54 [2] 4e 4c [2] 09 4e [2] 4e 5f [2] 00 53 [2] 0c 59 [2] 1b 52 [2] 00 1c [2] 3d }

  condition:
    any of them
}