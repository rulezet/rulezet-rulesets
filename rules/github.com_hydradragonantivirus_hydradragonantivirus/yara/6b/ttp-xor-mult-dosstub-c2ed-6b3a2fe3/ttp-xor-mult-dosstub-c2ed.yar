rule TTP_XOR_MULT_DOSStub_c2ed {
  strings:
    $key_c2ed = { 96 85 [2] e2 9d [2] a5 9f [2] e2 8e [2] ac 82 [2] a0 88 [2] b7 83 [2] ac cd [2] 91 }

  condition:
    any of them
}