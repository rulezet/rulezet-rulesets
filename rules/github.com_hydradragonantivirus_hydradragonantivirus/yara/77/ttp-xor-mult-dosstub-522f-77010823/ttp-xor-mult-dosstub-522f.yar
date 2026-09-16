rule TTP_XOR_MULT_DOSStub_522f {
  strings:
    $key_522f = { 06 47 [2] 72 5f [2] 35 5d [2] 72 4c [2] 3c 40 [2] 30 4a [2] 27 41 [2] 3c 0f [2] 01 }

  condition:
    any of them
}