rule TTP_XOR_MULT_DOSStub_24ae {
  strings:
    $key_24ae = { 70 c6 [2] 04 de [2] 43 dc [2] 04 cd [2] 4a c1 [2] 46 cb [2] 51 c0 [2] 4a 8e [2] 77 }

  condition:
    any of them
}