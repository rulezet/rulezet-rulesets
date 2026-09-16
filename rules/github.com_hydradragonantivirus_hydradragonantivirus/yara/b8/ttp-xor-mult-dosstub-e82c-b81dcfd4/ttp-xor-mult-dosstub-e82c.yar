rule TTP_XOR_MULT_DOSStub_e82c {
  strings:
    $key_e82c = { bc 44 [2] c8 5c [2] 8f 5e [2] c8 4f [2] 86 43 [2] 8a 49 [2] 9d 42 [2] 86 0c [2] bb }

  condition:
    any of them
}