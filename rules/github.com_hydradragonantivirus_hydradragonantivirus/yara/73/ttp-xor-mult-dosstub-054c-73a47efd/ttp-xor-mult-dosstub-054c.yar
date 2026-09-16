rule TTP_XOR_MULT_DOSStub_054c {
  strings:
    $key_054c = { 51 24 [2] 25 3c [2] 62 3e [2] 25 2f [2] 6b 23 [2] 67 29 [2] 70 22 [2] 6b 6c [2] 56 }

  condition:
    any of them
}