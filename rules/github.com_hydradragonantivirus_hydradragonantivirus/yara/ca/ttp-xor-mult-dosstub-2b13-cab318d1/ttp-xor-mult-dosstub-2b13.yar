rule TTP_XOR_MULT_DOSStub_2b13 {
  strings:
    $key_2b13 = { 7f 7b [2] 0b 63 [2] 4c 61 [2] 0b 70 [2] 45 7c [2] 49 76 [2] 5e 7d [2] 45 33 [2] 78 }

  condition:
    any of them
}