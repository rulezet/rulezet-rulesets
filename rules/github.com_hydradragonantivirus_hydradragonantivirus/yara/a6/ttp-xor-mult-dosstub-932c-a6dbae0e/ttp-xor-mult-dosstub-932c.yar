rule TTP_XOR_MULT_DOSStub_932c {
  strings:
    $key_932c = { c7 44 [2] b3 5c [2] f4 5e [2] b3 4f [2] fd 43 [2] f1 49 [2] e6 42 [2] fd 0c [2] c0 }

  condition:
    any of them
}