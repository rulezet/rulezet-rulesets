rule TTP_XOR_MULT_DOSStub_662f {
  strings:
    $key_662f = { 32 47 [2] 46 5f [2] 01 5d [2] 46 4c [2] 08 40 [2] 04 4a [2] 13 41 [2] 08 0f [2] 35 }

  condition:
    any of them
}