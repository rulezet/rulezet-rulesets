rule TTP_XOR_MULT_DOSStub_736c {
  strings:
    $key_736c = { 27 04 [2] 53 1c [2] 14 1e [2] 53 0f [2] 1d 03 [2] 11 09 [2] 06 02 [2] 1d 4c [2] 20 }

  condition:
    any of them
}