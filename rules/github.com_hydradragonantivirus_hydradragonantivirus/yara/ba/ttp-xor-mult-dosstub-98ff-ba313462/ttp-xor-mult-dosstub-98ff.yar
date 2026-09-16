rule TTP_XOR_MULT_DOSStub_98ff {
  strings:
    $key_98ff = { cc 97 [2] b8 8f [2] ff 8d [2] b8 9c [2] f6 90 [2] fa 9a [2] ed 91 [2] f6 df [2] cb }

  condition:
    any of them
}