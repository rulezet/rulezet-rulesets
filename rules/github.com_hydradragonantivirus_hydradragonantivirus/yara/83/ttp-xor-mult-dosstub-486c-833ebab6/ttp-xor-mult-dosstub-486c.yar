rule TTP_XOR_MULT_DOSStub_486c {
  strings:
    $key_486c = { 1c 04 [2] 68 1c [2] 2f 1e [2] 68 0f [2] 26 03 [2] 2a 09 [2] 3d 02 [2] 26 4c [2] 1b }

  condition:
    any of them
}