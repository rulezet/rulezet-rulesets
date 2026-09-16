rule TTP_XOR_MULT_DOSStub_6a6c {
  strings:
    $key_6a6c = { 3e 04 [2] 4a 1c [2] 0d 1e [2] 4a 0f [2] 04 03 [2] 08 09 [2] 1f 02 [2] 04 4c [2] 39 }

  condition:
    any of them
}