rule TTP_XOR_MULT_DOSStub_052e {
  strings:
    $key_052e = { 51 46 [2] 25 5e [2] 62 5c [2] 25 4d [2] 6b 41 [2] 67 4b [2] 70 40 [2] 6b 0e [2] 56 }

  condition:
    any of them
}