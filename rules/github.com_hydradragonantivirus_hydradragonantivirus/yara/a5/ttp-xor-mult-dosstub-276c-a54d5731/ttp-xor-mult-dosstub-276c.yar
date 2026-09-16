rule TTP_XOR_MULT_DOSStub_276c {
  strings:
    $key_276c = { 73 04 [2] 07 1c [2] 40 1e [2] 07 0f [2] 49 03 [2] 45 09 [2] 52 02 [2] 49 4c [2] 74 }

  condition:
    any of them
}