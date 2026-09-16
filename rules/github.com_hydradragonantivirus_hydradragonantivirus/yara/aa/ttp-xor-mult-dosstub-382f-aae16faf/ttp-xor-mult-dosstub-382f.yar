rule TTP_XOR_MULT_DOSStub_382f {
  strings:
    $key_382f = { 6c 47 [2] 18 5f [2] 5f 5d [2] 18 4c [2] 56 40 [2] 5a 4a [2] 4d 41 [2] 56 0f [2] 6b }

  condition:
    any of them
}