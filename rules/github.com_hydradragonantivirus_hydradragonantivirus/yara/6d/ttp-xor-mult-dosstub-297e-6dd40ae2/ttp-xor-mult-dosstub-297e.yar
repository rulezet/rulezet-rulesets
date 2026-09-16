rule TTP_XOR_MULT_DOSStub_297e {
  strings:
    $key_297e = { 7d 16 [2] 09 0e [2] 4e 0c [2] 09 1d [2] 47 11 [2] 4b 1b [2] 5c 10 [2] 47 5e [2] 7a }

  condition:
    any of them
}