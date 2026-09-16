rule TTP_XOR_MULT_DOSStub_092f {
  strings:
    $key_092f = { 5d 47 [2] 29 5f [2] 6e 5d [2] 29 4c [2] 67 40 [2] 6b 4a [2] 7c 41 [2] 67 0f [2] 5a }

  condition:
    any of them
}