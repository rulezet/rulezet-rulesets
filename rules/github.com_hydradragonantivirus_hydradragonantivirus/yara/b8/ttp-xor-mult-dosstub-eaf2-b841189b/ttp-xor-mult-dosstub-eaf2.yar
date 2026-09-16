rule TTP_XOR_MULT_DOSStub_eaf2 {
  strings:
    $key_eaf2 = { be 9a [2] ca 82 [2] 8d 80 [2] ca 91 [2] 84 9d [2] 88 97 [2] 9f 9c [2] 84 d2 [2] b9 }

  condition:
    any of them
}