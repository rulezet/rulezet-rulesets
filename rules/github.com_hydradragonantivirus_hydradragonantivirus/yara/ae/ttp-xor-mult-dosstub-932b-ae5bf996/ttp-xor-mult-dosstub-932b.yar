rule TTP_XOR_MULT_DOSStub_932b {
  strings:
    $key_932b = { c7 43 [2] b3 5b [2] f4 59 [2] b3 48 [2] fd 44 [2] f1 4e [2] e6 45 [2] fd 0b [2] c0 }

  condition:
    any of them
}