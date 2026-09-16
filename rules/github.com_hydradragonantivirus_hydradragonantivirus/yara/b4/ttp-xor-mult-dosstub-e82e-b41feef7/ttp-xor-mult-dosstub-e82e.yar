rule TTP_XOR_MULT_DOSStub_e82e {
  strings:
    $key_e82e = { bc 46 [2] c8 5e [2] 8f 5c [2] c8 4d [2] 86 41 [2] 8a 4b [2] 9d 40 [2] 86 0e [2] bb }

  condition:
    any of them
}