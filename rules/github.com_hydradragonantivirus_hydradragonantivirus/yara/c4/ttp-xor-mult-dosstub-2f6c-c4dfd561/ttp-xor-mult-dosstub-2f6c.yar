rule TTP_XOR_MULT_DOSStub_2f6c {
  strings:
    $key_2f6c = { 7b 04 [2] 0f 1c [2] 48 1e [2] 0f 0f [2] 41 03 [2] 4d 09 [2] 5a 02 [2] 41 4c [2] 7c }

  condition:
    any of them
}