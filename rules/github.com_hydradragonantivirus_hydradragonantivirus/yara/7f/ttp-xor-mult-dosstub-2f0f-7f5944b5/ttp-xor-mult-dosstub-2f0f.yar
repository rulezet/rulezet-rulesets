rule TTP_XOR_MULT_DOSStub_2f0f {
  strings:
    $key_2f0f = { 7b 67 [2] 0f 7f [2] 48 7d [2] 0f 6c [2] 41 60 [2] 4d 6a [2] 5a 61 [2] 41 2f [2] 7c }

  condition:
    any of them
}