rule TTP_XOR_MULT_DOSStub_021d {
  strings:
    $key_021d = { 56 75 [2] 22 6d [2] 65 6f [2] 22 7e [2] 6c 72 [2] 60 78 [2] 77 73 [2] 6c 3d [2] 51 }

  condition:
    any of them
}