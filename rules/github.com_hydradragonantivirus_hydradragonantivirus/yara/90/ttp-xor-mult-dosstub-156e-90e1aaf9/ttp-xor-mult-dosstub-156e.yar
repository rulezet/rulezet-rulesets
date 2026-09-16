rule TTP_XOR_MULT_DOSStub_156e {
  strings:
    $key_156e = { 41 06 [2] 35 1e [2] 72 1c [2] 35 0d [2] 7b 01 [2] 77 0b [2] 60 00 [2] 7b 4e [2] 46 }

  condition:
    any of them
}