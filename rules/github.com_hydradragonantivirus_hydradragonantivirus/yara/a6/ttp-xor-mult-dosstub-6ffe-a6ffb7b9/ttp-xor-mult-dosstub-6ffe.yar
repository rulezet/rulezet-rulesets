rule TTP_XOR_MULT_DOSStub_6ffe {
  strings:
    $key_6ffe = { 3b 96 [2] 4f 8e [2] 08 8c [2] 4f 9d [2] 01 91 [2] 0d 9b [2] 1a 90 [2] 01 de [2] 3c }

  condition:
    any of them
}