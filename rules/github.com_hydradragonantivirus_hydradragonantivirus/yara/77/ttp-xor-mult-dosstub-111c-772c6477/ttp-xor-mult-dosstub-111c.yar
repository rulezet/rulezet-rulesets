rule TTP_XOR_MULT_DOSStub_111c {
  strings:
    $key_111c = { 45 74 [2] 31 6c [2] 76 6e [2] 31 7f [2] 7f 73 [2] 73 79 [2] 64 72 [2] 7f 3c [2] 42 }

  condition:
    any of them
}