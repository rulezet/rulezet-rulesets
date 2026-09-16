rule TTP_XOR_MULT_DOSStub_236c {
  strings:
    $key_236c = { 77 04 [2] 03 1c [2] 44 1e [2] 03 0f [2] 4d 03 [2] 41 09 [2] 56 02 [2] 4d 4c [2] 70 }

  condition:
    any of them
}