rule TTP_XOR_MULT_DOSStub_024c {
  strings:
    $key_024c = { 56 24 [2] 22 3c [2] 65 3e [2] 22 2f [2] 6c 23 [2] 60 29 [2] 77 22 [2] 6c 6c [2] 51 }

  condition:
    any of them
}