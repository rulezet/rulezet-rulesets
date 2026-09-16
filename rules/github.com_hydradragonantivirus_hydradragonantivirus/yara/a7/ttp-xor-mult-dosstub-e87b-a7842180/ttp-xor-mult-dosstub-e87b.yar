rule TTP_XOR_MULT_DOSStub_e87b {
  strings:
    $key_e87b = { bc 13 [2] c8 0b [2] 8f 09 [2] c8 18 [2] 86 14 [2] 8a 1e [2] 9d 15 [2] 86 5b [2] bb }

  condition:
    any of them
}