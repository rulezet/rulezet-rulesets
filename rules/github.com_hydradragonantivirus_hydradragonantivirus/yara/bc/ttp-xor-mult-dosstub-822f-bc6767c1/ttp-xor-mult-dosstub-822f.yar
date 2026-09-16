rule TTP_XOR_MULT_DOSStub_822f {
  strings:
    $key_822f = { d6 47 [2] a2 5f [2] e5 5d [2] a2 4c [2] ec 40 [2] e0 4a [2] f7 41 [2] ec 0f [2] d1 }

  condition:
    any of them
}