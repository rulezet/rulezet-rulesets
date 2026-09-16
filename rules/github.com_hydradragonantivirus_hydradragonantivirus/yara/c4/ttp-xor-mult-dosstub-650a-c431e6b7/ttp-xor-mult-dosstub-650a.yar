rule TTP_XOR_MULT_DOSStub_650a {
  strings:
    $key_650a = { 31 62 [2] 45 7a [2] 02 78 [2] 45 69 [2] 0b 65 [2] 07 6f [2] 10 64 [2] 0b 2a [2] 36 }

  condition:
    any of them
}