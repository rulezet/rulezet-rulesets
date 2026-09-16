rule TTP_XOR_MULT_DOSStub_6e6c {
  strings:
    $key_6e6c = { 3a 04 [2] 4e 1c [2] 09 1e [2] 4e 0f [2] 00 03 [2] 0c 09 [2] 1b 02 [2] 00 4c [2] 3d }

  condition:
    any of them
}