rule TTP_XOR_MULT_DOSStub_056c {
  strings:
    $key_056c = { 51 04 [2] 25 1c [2] 62 1e [2] 25 0f [2] 6b 03 [2] 67 09 [2] 70 02 [2] 6b 4c [2] 56 }

  condition:
    any of them
}