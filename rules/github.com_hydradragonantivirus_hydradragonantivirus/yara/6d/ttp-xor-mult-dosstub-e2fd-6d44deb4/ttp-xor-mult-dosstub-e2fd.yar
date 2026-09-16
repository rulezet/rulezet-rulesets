rule TTP_XOR_MULT_DOSStub_e2fd {
  strings:
    $key_e2fd = { b6 95 [2] c2 8d [2] 85 8f [2] c2 9e [2] 8c 92 [2] 80 98 [2] 97 93 [2] 8c dd [2] b1 }

  condition:
    any of them
}