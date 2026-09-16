rule TTP_XOR_MULT_DOSStub_392b {
  strings:
    $key_392b = { 6d 43 [2] 19 5b [2] 5e 59 [2] 19 48 [2] 57 44 [2] 5b 4e [2] 4c 45 [2] 57 0b [2] 6a }

  condition:
    any of them
}