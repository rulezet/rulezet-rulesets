rule TTP_XOR_MULT_DOSStub_5cfe {
  strings:
    $key_5cfe = { 08 96 [2] 7c 8e [2] 3b 8c [2] 7c 9d [2] 32 91 [2] 3e 9b [2] 29 90 [2] 32 de [2] 0f }

  condition:
    any of them
}