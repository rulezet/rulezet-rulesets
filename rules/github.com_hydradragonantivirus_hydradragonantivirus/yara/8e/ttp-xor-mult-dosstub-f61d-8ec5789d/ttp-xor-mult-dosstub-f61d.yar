rule TTP_XOR_MULT_DOSStub_f61d {
  strings:
    $key_f61d = { a2 75 [2] d6 6d [2] 91 6f [2] d6 7e [2] 98 72 [2] 94 78 [2] 83 73 [2] 98 3d [2] a5 }

  condition:
    any of them
}