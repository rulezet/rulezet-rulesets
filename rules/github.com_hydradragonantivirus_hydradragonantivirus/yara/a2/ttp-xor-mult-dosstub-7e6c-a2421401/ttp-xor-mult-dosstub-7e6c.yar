rule TTP_XOR_MULT_DOSStub_7e6c {
  strings:
    $key_7e6c = { 2a 04 [2] 5e 1c [2] 19 1e [2] 5e 0f [2] 10 03 [2] 1c 09 [2] 0b 02 [2] 10 4c [2] 2d }

  condition:
    any of them
}