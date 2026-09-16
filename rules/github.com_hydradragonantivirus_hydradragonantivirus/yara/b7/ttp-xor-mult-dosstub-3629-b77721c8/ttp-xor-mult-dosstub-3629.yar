rule TTP_XOR_MULT_DOSStub_3629 {
  strings:
    $key_3629 = { 62 41 [2] 16 59 [2] 51 5b [2] 16 4a [2] 58 46 [2] 54 4c [2] 43 47 [2] 58 09 [2] 65 }

  condition:
    any of them
}