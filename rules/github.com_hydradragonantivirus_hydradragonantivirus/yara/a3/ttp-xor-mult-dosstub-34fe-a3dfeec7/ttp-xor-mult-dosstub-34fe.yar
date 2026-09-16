rule TTP_XOR_MULT_DOSStub_34fe {
  strings:
    $key_34fe = { 60 96 [2] 14 8e [2] 53 8c [2] 14 9d [2] 5a 91 [2] 56 9b [2] 41 90 [2] 5a de [2] 67 }

  condition:
    any of them
}