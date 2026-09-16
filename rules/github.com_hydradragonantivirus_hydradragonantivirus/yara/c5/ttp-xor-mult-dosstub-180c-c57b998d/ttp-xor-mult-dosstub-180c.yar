rule TTP_XOR_MULT_DOSStub_180c {
  strings:
    $key_180c = { 4c 64 [2] 38 7c [2] 7f 7e [2] 38 6f [2] 76 63 [2] 7a 69 [2] 6d 62 [2] 76 2c [2] 4b }

  condition:
    any of them
}