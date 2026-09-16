rule TTP_XOR_MULT_DOSStub_2be3 {
  strings:
    $key_2be3 = { 7f 8b [2] 0b 93 [2] 4c 91 [2] 0b 80 [2] 45 8c [2] 49 86 [2] 5e 8d [2] 45 c3 [2] 78 }

  condition:
    any of them
}