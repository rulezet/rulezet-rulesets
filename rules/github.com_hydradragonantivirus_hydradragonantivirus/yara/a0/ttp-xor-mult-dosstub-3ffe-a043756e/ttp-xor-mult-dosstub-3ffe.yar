rule TTP_XOR_MULT_DOSStub_3ffe {
  strings:
    $key_3ffe = { 6b 96 [2] 1f 8e [2] 58 8c [2] 1f 9d [2] 51 91 [2] 5d 9b [2] 4a 90 [2] 51 de [2] 6c }

  condition:
    any of them
}