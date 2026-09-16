rule TTP_XOR_MULT_DOSStub_9ffd {
  strings:
    $key_9ffd = { cb 95 [2] bf 8d [2] f8 8f [2] bf 9e [2] f1 92 [2] fd 98 [2] ea 93 [2] f1 dd [2] cc }

  condition:
    any of them
}