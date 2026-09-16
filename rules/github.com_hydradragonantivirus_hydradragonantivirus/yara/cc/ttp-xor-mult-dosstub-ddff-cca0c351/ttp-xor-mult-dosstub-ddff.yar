rule TTP_XOR_MULT_DOSStub_ddff {
  strings:
    $key_ddff = { 89 97 [2] fd 8f [2] ba 8d [2] fd 9c [2] b3 90 [2] bf 9a [2] a8 91 [2] b3 df [2] 8e }

  condition:
    any of them
}