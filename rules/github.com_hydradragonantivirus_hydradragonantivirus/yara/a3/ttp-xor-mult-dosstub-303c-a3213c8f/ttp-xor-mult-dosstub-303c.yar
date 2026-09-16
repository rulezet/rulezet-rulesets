rule TTP_XOR_MULT_DOSStub_303c {
  strings:
    $key_303c = { 64 54 [2] 10 4c [2] 57 4e [2] 10 5f [2] 5e 53 [2] 52 59 [2] 45 52 [2] 5e 1c [2] 63 }

  condition:
    any of them
}