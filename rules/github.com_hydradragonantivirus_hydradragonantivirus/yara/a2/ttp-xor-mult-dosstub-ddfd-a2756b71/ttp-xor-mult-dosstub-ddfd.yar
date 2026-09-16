rule TTP_XOR_MULT_DOSStub_ddfd {
  strings:
    $key_ddfd = { 89 95 [2] fd 8d [2] ba 8f [2] fd 9e [2] b3 92 [2] bf 98 [2] a8 93 [2] b3 dd [2] 8e }

  condition:
    any of them
}