rule TTP_XOR_MULT_DOSStub_f34d {
  strings:
    $key_f34d = { a7 25 [2] d3 3d [2] 94 3f [2] d3 2e [2] 9d 22 [2] 91 28 [2] 86 23 [2] 9d 6d [2] a0 }

  condition:
    any of them
}