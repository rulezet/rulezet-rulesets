rule TTP_XOR_MULT_DOSStub_2cfe {
  strings:
    $key_2cfe = { 78 96 [2] 0c 8e [2] 4b 8c [2] 0c 9d [2] 42 91 [2] 4e 9b [2] 59 90 [2] 42 de [2] 7f }

  condition:
    any of them
}