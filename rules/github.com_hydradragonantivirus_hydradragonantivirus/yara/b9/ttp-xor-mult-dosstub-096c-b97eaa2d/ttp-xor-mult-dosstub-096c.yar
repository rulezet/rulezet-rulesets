rule TTP_XOR_MULT_DOSStub_096c {
  strings:
    $key_096c = { 5d 04 [2] 29 1c [2] 6e 1e [2] 29 0f [2] 67 03 [2] 6b 09 [2] 7c 02 [2] 67 4c [2] 5a }

  condition:
    any of them
}