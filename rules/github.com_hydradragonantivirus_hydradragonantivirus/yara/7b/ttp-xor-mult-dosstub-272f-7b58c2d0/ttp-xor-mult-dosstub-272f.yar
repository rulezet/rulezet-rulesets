rule TTP_XOR_MULT_DOSStub_272f {
  strings:
    $key_272f = { 73 47 [2] 07 5f [2] 40 5d [2] 07 4c [2] 49 40 [2] 45 4a [2] 52 41 [2] 49 0f [2] 74 }

  condition:
    any of them
}