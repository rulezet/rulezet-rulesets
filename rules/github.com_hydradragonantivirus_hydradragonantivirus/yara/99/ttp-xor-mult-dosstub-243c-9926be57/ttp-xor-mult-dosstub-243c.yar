rule TTP_XOR_MULT_DOSStub_243c {
  strings:
    $key_243c = { 70 54 [2] 04 4c [2] 43 4e [2] 04 5f [2] 4a 53 [2] 46 59 [2] 51 52 [2] 4a 1c [2] 77 }

  condition:
    any of them
}