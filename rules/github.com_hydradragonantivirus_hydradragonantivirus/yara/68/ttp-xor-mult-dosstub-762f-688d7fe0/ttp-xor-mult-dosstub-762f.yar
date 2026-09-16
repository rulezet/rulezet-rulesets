rule TTP_XOR_MULT_DOSStub_762f {
  strings:
    $key_762f = { 22 47 [2] 56 5f [2] 11 5d [2] 56 4c [2] 18 40 [2] 14 4a [2] 03 41 [2] 18 0f [2] 25 }

  condition:
    any of them
}