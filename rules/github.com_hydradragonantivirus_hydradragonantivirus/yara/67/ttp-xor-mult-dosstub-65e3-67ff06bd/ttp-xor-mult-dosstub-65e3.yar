rule TTP_XOR_MULT_DOSStub_65e3 {
  strings:
    $key_65e3 = { 31 8b [2] 45 93 [2] 02 91 [2] 45 80 [2] 0b 8c [2] 07 86 [2] 10 8d [2] 0b c3 [2] 36 }

  condition:
    any of them
}