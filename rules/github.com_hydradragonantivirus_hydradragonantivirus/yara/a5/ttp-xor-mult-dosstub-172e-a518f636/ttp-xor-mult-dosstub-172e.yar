rule TTP_XOR_MULT_DOSStub_172e {
  strings:
    $key_172e = { 43 46 [2] 37 5e [2] 70 5c [2] 37 4d [2] 79 41 [2] 75 4b [2] 62 40 [2] 79 0e [2] 44 }

  condition:
    any of them
}