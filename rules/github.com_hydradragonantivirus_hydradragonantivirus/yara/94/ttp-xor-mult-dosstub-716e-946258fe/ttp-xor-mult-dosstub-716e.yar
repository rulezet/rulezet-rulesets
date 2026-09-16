rule TTP_XOR_MULT_DOSStub_716e {
  strings:
    $key_716e = { 25 06 [2] 51 1e [2] 16 1c [2] 51 0d [2] 1f 01 [2] 13 0b [2] 04 00 [2] 1f 4e [2] 22 }

  condition:
    any of them
}