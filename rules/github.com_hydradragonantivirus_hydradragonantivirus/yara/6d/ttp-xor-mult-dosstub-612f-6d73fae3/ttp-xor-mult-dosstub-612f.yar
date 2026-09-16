rule TTP_XOR_MULT_DOSStub_612f {
  strings:
    $key_612f = { 35 47 [2] 41 5f [2] 06 5d [2] 41 4c [2] 0f 40 [2] 03 4a [2] 14 41 [2] 0f 0f [2] 32 }

  condition:
    any of them
}