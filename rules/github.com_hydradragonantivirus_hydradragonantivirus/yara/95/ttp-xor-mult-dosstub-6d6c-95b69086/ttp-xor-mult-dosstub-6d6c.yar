rule TTP_XOR_MULT_DOSStub_6d6c {
  strings:
    $key_6d6c = { 39 04 [2] 4d 1c [2] 0a 1e [2] 4d 0f [2] 03 03 [2] 0f 09 [2] 18 02 [2] 03 4c [2] 3e }

  condition:
    any of them
}