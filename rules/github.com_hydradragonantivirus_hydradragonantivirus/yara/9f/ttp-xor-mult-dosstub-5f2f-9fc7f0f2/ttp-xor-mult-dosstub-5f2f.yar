rule TTP_XOR_MULT_DOSStub_5f2f {
  strings:
    $key_5f2f = { 0b 47 [2] 7f 5f [2] 38 5d [2] 7f 4c [2] 31 40 [2] 3d 4a [2] 2a 41 [2] 31 0f [2] 0c }

  condition:
    any of them
}