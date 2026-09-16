rule TTP_XOR_MULT_DOSStub_eefe {
  strings:
    $key_eefe = { ba 96 [2] ce 8e [2] 89 8c [2] ce 9d [2] 80 91 [2] 8c 9b [2] 9b 90 [2] 80 de [2] bd }

  condition:
    any of them
}