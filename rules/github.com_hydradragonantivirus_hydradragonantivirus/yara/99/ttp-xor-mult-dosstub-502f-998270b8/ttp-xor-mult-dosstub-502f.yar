rule TTP_XOR_MULT_DOSStub_502f {
  strings:
    $key_502f = { 04 47 [2] 70 5f [2] 37 5d [2] 70 4c [2] 3e 40 [2] 32 4a [2] 25 41 [2] 3e 0f [2] 03 }

  condition:
    any of them
}