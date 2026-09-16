rule TTP_XOR_MULT_DOSStub_e23c {
  strings:
    $key_e23c = { b6 54 [2] c2 4c [2] 85 4e [2] c2 5f [2] 8c 53 [2] 80 59 [2] 97 52 [2] 8c 1c [2] b1 }

  condition:
    any of them
}