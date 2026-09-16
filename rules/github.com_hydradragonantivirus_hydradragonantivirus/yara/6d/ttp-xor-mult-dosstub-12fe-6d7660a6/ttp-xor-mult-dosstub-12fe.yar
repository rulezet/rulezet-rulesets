rule TTP_XOR_MULT_DOSStub_12fe {
  strings:
    $key_12fe = { 46 96 [2] 32 8e [2] 75 8c [2] 32 9d [2] 7c 91 [2] 70 9b [2] 67 90 [2] 7c de [2] 41 }

  condition:
    any of them
}