rule TTP_XOR_MULT_DOSStub_7b6c {
  strings:
    $key_7b6c = { 2f 04 [2] 5b 1c [2] 1c 1e [2] 5b 0f [2] 15 03 [2] 19 09 [2] 0e 02 [2] 15 4c [2] 28 }

  condition:
    any of them
}