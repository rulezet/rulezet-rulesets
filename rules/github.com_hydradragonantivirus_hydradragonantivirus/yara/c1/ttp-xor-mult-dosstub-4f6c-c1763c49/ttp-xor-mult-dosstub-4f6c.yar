rule TTP_XOR_MULT_DOSStub_4f6c {
  strings:
    $key_4f6c = { 1b 04 [2] 6f 1c [2] 28 1e [2] 6f 0f [2] 21 03 [2] 2d 09 [2] 3a 02 [2] 21 4c [2] 1c }

  condition:
    any of them
}