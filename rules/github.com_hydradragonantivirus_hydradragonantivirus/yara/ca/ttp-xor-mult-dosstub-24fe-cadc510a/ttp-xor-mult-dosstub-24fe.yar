rule TTP_XOR_MULT_DOSStub_24fe {
  strings:
    $key_24fe = { 70 96 [2] 04 8e [2] 43 8c [2] 04 9d [2] 4a 91 [2] 46 9b [2] 51 90 [2] 4a de [2] 77 }

  condition:
    any of them
}