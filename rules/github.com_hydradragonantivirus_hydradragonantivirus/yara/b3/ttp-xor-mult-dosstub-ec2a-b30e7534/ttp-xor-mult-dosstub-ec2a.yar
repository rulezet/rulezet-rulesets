rule TTP_XOR_MULT_DOSStub_ec2a {
  strings:
    $key_ec2a = { b8 42 [2] cc 5a [2] 8b 58 [2] cc 49 [2] 82 45 [2] 8e 4f [2] 99 44 [2] 82 0a [2] bf }

  condition:
    any of them
}