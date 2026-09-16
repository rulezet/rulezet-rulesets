rule TTP_XOR_MULT_DOSStub_067c {
  strings:
    $key_067c = { 52 14 [2] 26 0c [2] 61 0e [2] 26 1f [2] 68 13 [2] 64 19 [2] 73 12 [2] 68 5c [2] 55 }

  condition:
    any of them
}