rule TTP_XOR_MULT_DOSStub_936c {
  strings:
    $key_936c = { c7 04 [2] b3 1c [2] f4 1e [2] b3 0f [2] fd 03 [2] f1 09 [2] e6 02 [2] fd 4c [2] c0 }

  condition:
    any of them
}