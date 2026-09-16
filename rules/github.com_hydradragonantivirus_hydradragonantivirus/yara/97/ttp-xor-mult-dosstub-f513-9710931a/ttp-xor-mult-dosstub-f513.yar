rule TTP_XOR_MULT_DOSStub_f513 {
  strings:
    $key_f513 = { a1 7b [2] d5 63 [2] 92 61 [2] d5 70 [2] 9b 7c [2] 97 76 [2] 80 7d [2] 9b 33 [2] a6 }

  condition:
    any of them
}