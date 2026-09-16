rule TTP_XOR_MULT_DOSStub_2717 {
  strings:
    $key_2717 = { 73 7f [2] 07 67 [2] 40 65 [2] 07 74 [2] 49 78 [2] 45 72 [2] 52 79 [2] 49 37 [2] 74 }

  condition:
    any of them
}