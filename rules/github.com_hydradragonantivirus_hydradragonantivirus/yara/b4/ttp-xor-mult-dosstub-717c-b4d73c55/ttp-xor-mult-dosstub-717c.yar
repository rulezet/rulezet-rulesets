rule TTP_XOR_MULT_DOSStub_717c {
  strings:
    $key_717c = { 25 14 [2] 51 0c [2] 16 0e [2] 51 1f [2] 1f 13 [2] 13 19 [2] 04 12 [2] 1f 5c [2] 22 }

  condition:
    any of them
}