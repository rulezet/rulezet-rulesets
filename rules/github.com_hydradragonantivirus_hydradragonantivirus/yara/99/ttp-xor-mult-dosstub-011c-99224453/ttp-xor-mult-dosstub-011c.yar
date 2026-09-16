rule TTP_XOR_MULT_DOSStub_011c {
  strings:
    $key_011c = { 55 74 [2] 21 6c [2] 66 6e [2] 21 7f [2] 6f 73 [2] 63 79 [2] 74 72 [2] 6f 3c [2] 52 }

  condition:
    any of them
}