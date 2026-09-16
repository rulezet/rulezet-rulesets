rule TTP_XOR_MULT_DOSStub_1e6c {
  strings:
    $key_1e6c = { 4a 04 [2] 3e 1c [2] 79 1e [2] 3e 0f [2] 70 03 [2] 7c 09 [2] 6b 02 [2] 70 4c [2] 4d }

  condition:
    any of them
}