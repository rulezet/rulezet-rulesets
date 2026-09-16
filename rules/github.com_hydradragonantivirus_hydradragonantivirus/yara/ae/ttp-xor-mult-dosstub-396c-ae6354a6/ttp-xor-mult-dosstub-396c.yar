rule TTP_XOR_MULT_DOSStub_396c {
  strings:
    $key_396c = { 6d 04 [2] 19 1c [2] 5e 1e [2] 19 0f [2] 57 03 [2] 5b 09 [2] 4c 02 [2] 57 4c [2] 6a }

  condition:
    any of them
}