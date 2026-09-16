rule TTP_XOR_MULT_DOSStub_2b6f {
  strings:
    $key_2b6f = { 7f 07 [2] 0b 1f [2] 4c 1d [2] 0b 0c [2] 45 00 [2] 49 0a [2] 5e 01 [2] 45 4f [2] 78 }

  condition:
    any of them
}