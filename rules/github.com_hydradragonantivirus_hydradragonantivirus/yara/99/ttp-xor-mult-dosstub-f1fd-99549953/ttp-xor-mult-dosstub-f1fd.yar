rule TTP_XOR_MULT_DOSStub_f1fd {
  strings:
    $key_f1fd = { a5 95 [2] d1 8d [2] 96 8f [2] d1 9e [2] 9f 92 [2] 93 98 [2] 84 93 [2] 9f dd [2] a2 }

  condition:
    any of them
}