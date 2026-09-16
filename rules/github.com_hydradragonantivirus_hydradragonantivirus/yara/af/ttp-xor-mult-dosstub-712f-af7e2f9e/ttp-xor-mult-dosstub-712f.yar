rule TTP_XOR_MULT_DOSStub_712f {
  strings:
    $key_712f = { 25 47 [2] 51 5f [2] 16 5d [2] 51 4c [2] 1f 40 [2] 13 4a [2] 04 41 [2] 1f 0f [2] 22 }

  condition:
    any of them
}