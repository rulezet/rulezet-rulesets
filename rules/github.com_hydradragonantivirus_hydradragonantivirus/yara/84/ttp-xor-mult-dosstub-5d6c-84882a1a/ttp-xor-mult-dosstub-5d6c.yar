rule TTP_XOR_MULT_DOSStub_5d6c {
  strings:
    $key_5d6c = { 09 04 [2] 7d 1c [2] 3a 1e [2] 7d 0f [2] 33 03 [2] 3f 09 [2] 28 02 [2] 33 4c [2] 0e }

  condition:
    any of them
}