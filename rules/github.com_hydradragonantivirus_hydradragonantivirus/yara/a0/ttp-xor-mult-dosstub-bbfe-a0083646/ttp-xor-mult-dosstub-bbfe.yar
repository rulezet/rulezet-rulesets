rule TTP_XOR_MULT_DOSStub_bbfe {
  strings:
    $key_bbfe = { ef 96 [2] 9b 8e [2] dc 8c [2] 9b 9d [2] d5 91 [2] d9 9b [2] ce 90 [2] d5 de [2] e8 }

  condition:
    any of them
}