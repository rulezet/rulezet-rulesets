rule TTP_XOR_MULT_DOSStub_27fc {
  strings:
    $key_27fc = { 73 94 [2] 07 8c [2] 40 8e [2] 07 9f [2] 49 93 [2] 45 99 [2] 52 92 [2] 49 dc [2] 74 }

  condition:
    any of them
}