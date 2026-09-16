rule TTP_XOR_MULT_DOSStub_1ffe {
  strings:
    $key_1ffe = { 4b 96 [2] 3f 8e [2] 78 8c [2] 3f 9d [2] 71 91 [2] 7d 9b [2] 6a 90 [2] 71 de [2] 4c }

  condition:
    any of them
}