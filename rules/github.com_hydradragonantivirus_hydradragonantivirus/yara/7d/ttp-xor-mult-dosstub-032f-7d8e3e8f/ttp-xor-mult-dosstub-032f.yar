rule TTP_XOR_MULT_DOSStub_032f {
  strings:
    $key_032f = { 57 47 [2] 23 5f [2] 64 5d [2] 23 4c [2] 6d 40 [2] 61 4a [2] 76 41 [2] 6d 0f [2] 50 }

  condition:
    any of them
}