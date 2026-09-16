rule TTP_XOR_MULT_DOSStub_3f7e {
  strings:
    $key_3f7e = { 6b 16 [2] 1f 0e [2] 58 0c [2] 1f 1d [2] 51 11 [2] 5d 1b [2] 4a 10 [2] 51 5e [2] 6c }

  condition:
    any of them
}