rule TTP_XOR_MULT_DOSStub_ee6c {
  strings:
    $key_ee6c = { ba 04 [2] ce 1c [2] 89 1e [2] ce 0f [2] 80 03 [2] 8c 09 [2] 9b 02 [2] 80 4c [2] bd }

  condition:
    any of them
}