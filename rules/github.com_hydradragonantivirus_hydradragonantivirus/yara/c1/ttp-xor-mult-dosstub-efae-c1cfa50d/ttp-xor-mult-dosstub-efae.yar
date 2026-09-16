rule TTP_XOR_MULT_DOSStub_efae {
  strings:
    $key_efae = { bb c6 [2] cf de [2] 88 dc [2] cf cd [2] 81 c1 [2] 8d cb [2] 9a c0 [2] 81 8e [2] bc }

  condition:
    any of them
}