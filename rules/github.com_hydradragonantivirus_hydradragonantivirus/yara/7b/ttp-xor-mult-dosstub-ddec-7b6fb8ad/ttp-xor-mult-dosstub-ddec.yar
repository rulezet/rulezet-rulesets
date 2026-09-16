rule TTP_XOR_MULT_DOSStub_ddec {
  strings:
    $key_ddec = { 89 84 [2] fd 9c [2] ba 9e [2] fd 8f [2] b3 83 [2] bf 89 [2] a8 82 [2] b3 cc [2] 8e }

  condition:
    any of them
}