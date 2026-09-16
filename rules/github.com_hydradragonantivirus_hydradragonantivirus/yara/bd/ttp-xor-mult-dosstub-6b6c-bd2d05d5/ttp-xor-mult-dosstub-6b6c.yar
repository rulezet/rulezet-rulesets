rule TTP_XOR_MULT_DOSStub_6b6c {
  strings:
    $key_6b6c = { 3f 04 [2] 4b 1c [2] 0c 1e [2] 4b 0f [2] 05 03 [2] 09 09 [2] 1e 02 [2] 05 4c [2] 38 }

  condition:
    any of them
}