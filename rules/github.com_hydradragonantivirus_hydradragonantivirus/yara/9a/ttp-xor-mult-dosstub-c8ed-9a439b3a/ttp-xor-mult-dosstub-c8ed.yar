rule TTP_XOR_MULT_DOSStub_c8ed {
  strings:
    $key_c8ed = { 9c 85 [2] e8 9d [2] af 9f [2] e8 8e [2] a6 82 [2] aa 88 [2] bd 83 [2] a6 cd [2] 9b }

  condition:
    any of them
}