rule TTP_XOR_MULT_DOSStub_121d {
  strings:
    $key_121d = { 46 75 [2] 32 6d [2] 75 6f [2] 32 7e [2] 7c 72 [2] 70 78 [2] 67 73 [2] 7c 3d [2] 41 }

  condition:
    any of them
}