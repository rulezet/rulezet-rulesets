rule TTP_XOR_MULT_DOSStub_00fe {
  strings:
    $key_00fe = { 54 96 [2] 20 8e [2] 67 8c [2] 20 9d [2] 6e 91 [2] 62 9b [2] 75 90 [2] 6e de [2] 53 }

  condition:
    any of them
}