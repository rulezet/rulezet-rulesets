rule TTP_XOR_MULT_DOSStub_663c {
  strings:
    $key_663c = { 32 54 [2] 46 4c [2] 01 4e [2] 46 5f [2] 08 53 [2] 04 59 [2] 13 52 [2] 08 1c [2] 35 }

  condition:
    any of them
}