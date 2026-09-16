rule TTP_XOR_MULT_DOSStub_6f2f {
  strings:
    $key_6f2f = { 3b 47 [2] 4f 5f [2] 08 5d [2] 4f 4c [2] 01 40 [2] 0d 4a [2] 1a 41 [2] 01 0f [2] 3c }

  condition:
    any of them
}