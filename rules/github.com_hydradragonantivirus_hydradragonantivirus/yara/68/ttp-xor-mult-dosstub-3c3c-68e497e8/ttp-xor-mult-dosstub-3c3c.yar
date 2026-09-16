rule TTP_XOR_MULT_DOSStub_3c3c {
  strings:
    $key_3c3c = { 68 54 [2] 1c 4c [2] 5b 4e [2] 1c 5f [2] 52 53 [2] 5e 59 [2] 49 52 [2] 52 1c [2] 6f }

  condition:
    any of them
}