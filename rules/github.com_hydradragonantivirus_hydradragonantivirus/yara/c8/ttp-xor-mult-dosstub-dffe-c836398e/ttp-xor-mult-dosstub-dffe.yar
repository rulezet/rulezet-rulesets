rule TTP_XOR_MULT_DOSStub_dffe {
  strings:
    $key_dffe = { 8b 96 [2] ff 8e [2] b8 8c [2] ff 9d [2] b1 91 [2] bd 9b [2] aa 90 [2] b1 de [2] 8c }

  condition:
    any of them
}