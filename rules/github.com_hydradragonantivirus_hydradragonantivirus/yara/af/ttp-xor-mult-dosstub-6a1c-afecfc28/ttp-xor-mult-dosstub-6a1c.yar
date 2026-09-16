rule TTP_XOR_MULT_DOSStub_6a1c {
  strings:
    $key_6a1c = { 3e 74 [2] 4a 6c [2] 0d 6e [2] 4a 7f [2] 04 73 [2] 08 79 [2] 1f 72 [2] 04 3c [2] 39 }

  condition:
    any of them
}