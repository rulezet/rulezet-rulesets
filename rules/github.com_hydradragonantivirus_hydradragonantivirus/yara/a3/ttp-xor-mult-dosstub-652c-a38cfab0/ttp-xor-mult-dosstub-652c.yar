rule TTP_XOR_MULT_DOSStub_652c {
  strings:
    $key_652c = { 31 44 [2] 45 5c [2] 02 5e [2] 45 4f [2] 0b 43 [2] 07 49 [2] 10 42 [2] 0b 0c [2] 36 }

  condition:
    any of them
}