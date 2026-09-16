rule TTP_XOR_MULT_DOSStub_2b0f {
  strings:
    $key_2b0f = { 7f 67 [2] 0b 7f [2] 4c 7d [2] 0b 6c [2] 45 60 [2] 49 6a [2] 5e 61 [2] 45 2f [2] 78 }

  condition:
    any of them
}