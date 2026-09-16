rule TTP_XOR_MULT_DOSStub_321d {
  strings:
    $key_321d = { 66 75 [2] 12 6d [2] 55 6f [2] 12 7e [2] 5c 72 [2] 50 78 [2] 47 73 [2] 5c 3d [2] 61 }

  condition:
    any of them
}