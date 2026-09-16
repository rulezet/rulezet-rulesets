rule TTP_XOR_MULT_DOSStub_55fc {
  strings:
    $key_55fc = { 01 94 [2] 75 8c [2] 32 8e [2] 75 9f [2] 3b 93 [2] 37 99 [2] 20 92 [2] 3b dc [2] 06 }

  condition:
    any of them
}