rule TTP_XOR_MULT_DOSStub_932a {
  strings:
    $key_932a = { c7 42 [2] b3 5a [2] f4 58 [2] b3 49 [2] fd 45 [2] f1 4f [2] e6 44 [2] fd 0a [2] c0 }

  condition:
    any of them
}