rule TTP_XOR_MULT_DOSStub_796c {
  strings:
    $key_796c = { 2d 04 [2] 59 1c [2] 1e 1e [2] 59 0f [2] 17 03 [2] 1b 09 [2] 0c 02 [2] 17 4c [2] 2a }

  condition:
    any of them
}