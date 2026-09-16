rule TTP_XOR_MULT_DOSStub_052f {
  strings:
    $key_052f = { 51 47 [2] 25 5f [2] 62 5d [2] 25 4c [2] 6b 40 [2] 67 4a [2] 70 41 [2] 6b 0f [2] 56 }

  condition:
    any of them
}