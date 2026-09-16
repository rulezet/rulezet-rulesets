rule TTP_XOR_MULT_DOSStub_664d {
  strings:
    $key_664d = { 32 25 [2] 46 3d [2] 01 3f [2] 46 2e [2] 08 22 [2] 04 28 [2] 13 23 [2] 08 6d [2] 35 }

  condition:
    any of them
}