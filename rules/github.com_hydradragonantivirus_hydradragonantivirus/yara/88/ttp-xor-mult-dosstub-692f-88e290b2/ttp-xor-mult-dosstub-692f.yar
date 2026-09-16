rule TTP_XOR_MULT_DOSStub_692f {
  strings:
    $key_692f = { 3d 47 [2] 49 5f [2] 0e 5d [2] 49 4c [2] 07 40 [2] 0b 4a [2] 1c 41 [2] 07 0f [2] 3a }

  condition:
    any of them
}