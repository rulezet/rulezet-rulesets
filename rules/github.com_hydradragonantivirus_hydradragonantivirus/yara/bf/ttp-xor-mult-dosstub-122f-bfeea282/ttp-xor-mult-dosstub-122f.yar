rule TTP_XOR_MULT_DOSStub_122f {
  strings:
    $key_122f = { 46 47 [2] 32 5f [2] 75 5d [2] 32 4c [2] 7c 40 [2] 70 4a [2] 67 41 [2] 7c 0f [2] 41 }

  condition:
    any of them
}