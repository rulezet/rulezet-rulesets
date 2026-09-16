rule TTP_XOR_MULT_DOSStub_131c {
  strings:
    $key_131c = { 47 74 [2] 33 6c [2] 74 6e [2] 33 7f [2] 7d 73 [2] 71 79 [2] 66 72 [2] 7d 3c [2] 40 }

  condition:
    any of them
}