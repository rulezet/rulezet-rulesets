rule TTP_XOR_MULT_DOSStub_664c {
  strings:
    $key_664c = { 32 24 [2] 46 3c [2] 01 3e [2] 46 2f [2] 08 23 [2] 04 29 [2] 13 22 [2] 08 6c [2] 35 }

  condition:
    any of them
}