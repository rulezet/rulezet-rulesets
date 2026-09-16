rule TTP_XOR_MULT_DOSStub_2d6c {
  strings:
    $key_2d6c = { 79 04 [2] 0d 1c [2] 4a 1e [2] 0d 0f [2] 43 03 [2] 4f 09 [2] 58 02 [2] 43 4c [2] 7e }

  condition:
    any of them
}