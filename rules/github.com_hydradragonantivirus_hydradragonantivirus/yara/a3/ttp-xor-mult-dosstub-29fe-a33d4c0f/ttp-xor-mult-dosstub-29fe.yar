rule TTP_XOR_MULT_DOSStub_29fe {
  strings:
    $key_29fe = { 7d 96 [2] 09 8e [2] 4e 8c [2] 09 9d [2] 47 91 [2] 4b 9b [2] 5c 90 [2] 47 de [2] 7a }

  condition:
    any of them
}