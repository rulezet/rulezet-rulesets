rule TTP_XOR_MULT_DOSStub_a1fe {
  strings:
    $key_a1fe = { f5 96 [2] 81 8e [2] c6 8c [2] 81 9d [2] cf 91 [2] c3 9b [2] d4 90 [2] cf de [2] f2 }

  condition:
    any of them
}