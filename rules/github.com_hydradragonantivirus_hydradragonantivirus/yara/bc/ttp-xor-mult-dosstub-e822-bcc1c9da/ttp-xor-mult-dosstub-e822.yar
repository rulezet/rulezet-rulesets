rule TTP_XOR_MULT_DOSStub_e822 {
  strings:
    $key_e822 = { bc 4a [2] c8 52 [2] 8f 50 [2] c8 41 [2] 86 4d [2] 8a 47 [2] 9d 4c [2] 86 02 [2] bb }

  condition:
    any of them
}