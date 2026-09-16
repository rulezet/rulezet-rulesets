rule TTP_XOR_MULT_DOSStub_142f {
  strings:
    $key_142f = { 40 47 [2] 34 5f [2] 73 5d [2] 34 4c [2] 7a 40 [2] 76 4a [2] 61 41 [2] 7a 0f [2] 47 }

  condition:
    any of them
}