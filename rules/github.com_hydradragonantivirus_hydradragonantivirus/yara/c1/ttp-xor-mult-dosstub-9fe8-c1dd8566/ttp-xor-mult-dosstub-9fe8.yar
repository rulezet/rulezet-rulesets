rule TTP_XOR_MULT_DOSStub_9fe8 {
  strings:
    $key_9fe8 = { cb 80 [2] bf 98 [2] f8 9a [2] bf 8b [2] f1 87 [2] fd 8d [2] ea 86 [2] f1 c8 [2] cc }

  condition:
    any of them
}