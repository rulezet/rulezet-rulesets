rule TTP_XOR_MULT_DOSStub_023c {
  strings:
    $key_023c = { 56 54 [2] 22 4c [2] 65 4e [2] 22 5f [2] 6c 53 [2] 60 59 [2] 77 52 [2] 6c 1c [2] 51 }

  condition:
    any of them
}