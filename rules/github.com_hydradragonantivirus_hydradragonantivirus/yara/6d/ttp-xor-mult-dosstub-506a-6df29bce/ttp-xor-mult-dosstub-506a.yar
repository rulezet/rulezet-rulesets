rule TTP_XOR_MULT_DOSStub_506a {
  strings:
    $key_506a = { 04 02 [2] 70 1a [2] 37 18 [2] 70 09 [2] 3e 05 [2] 32 0f [2] 25 04 [2] 3e 4a [2] 03 }

  condition:
    any of them
}