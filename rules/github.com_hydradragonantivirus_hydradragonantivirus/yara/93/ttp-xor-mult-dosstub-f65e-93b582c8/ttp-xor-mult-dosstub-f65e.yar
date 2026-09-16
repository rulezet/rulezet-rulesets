rule TTP_XOR_MULT_DOSStub_f65e {
  strings:
    $key_f65e = { a2 36 [2] d6 2e [2] 91 2c [2] d6 3d [2] 98 31 [2] 94 3b [2] 83 30 [2] 98 7e [2] a5 }

  condition:
    any of them
}