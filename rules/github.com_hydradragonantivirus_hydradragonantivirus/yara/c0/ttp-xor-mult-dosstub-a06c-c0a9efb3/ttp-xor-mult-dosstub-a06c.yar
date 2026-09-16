rule TTP_XOR_MULT_DOSStub_a06c {
  strings:
    $key_a06c = { f4 04 [2] 80 1c [2] c7 1e [2] 80 0f [2] ce 03 [2] c2 09 [2] d5 02 [2] ce 4c [2] f3 }

  condition:
    any of them
}