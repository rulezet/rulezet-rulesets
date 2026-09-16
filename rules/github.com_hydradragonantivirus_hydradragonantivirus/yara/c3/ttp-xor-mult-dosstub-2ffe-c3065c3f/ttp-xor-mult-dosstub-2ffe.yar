rule TTP_XOR_MULT_DOSStub_2ffe {
  strings:
    $key_2ffe = { 7b 96 [2] 0f 8e [2] 48 8c [2] 0f 9d [2] 41 91 [2] 4d 9b [2] 5a 90 [2] 41 de [2] 7c }

  condition:
    any of them
}