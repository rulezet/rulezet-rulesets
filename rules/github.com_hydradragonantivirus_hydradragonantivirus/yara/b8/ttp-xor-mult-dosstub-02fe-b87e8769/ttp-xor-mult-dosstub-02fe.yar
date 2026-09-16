rule TTP_XOR_MULT_DOSStub_02fe {
  strings:
    $key_02fe = { 56 96 [2] 22 8e [2] 65 8c [2] 22 9d [2] 6c 91 [2] 60 9b [2] 77 90 [2] 6c de [2] 51 }

  condition:
    any of them
}