rule TTP_XOR_MULT_DOSStub_273c {
  strings:
    $key_273c = { 73 54 [2] 07 4c [2] 40 4e [2] 07 5f [2] 49 53 [2] 45 59 [2] 52 52 [2] 49 1c [2] 74 }

  condition:
    any of them
}