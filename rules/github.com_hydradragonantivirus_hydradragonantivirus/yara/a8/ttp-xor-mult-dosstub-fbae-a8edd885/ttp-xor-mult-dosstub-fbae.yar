rule TTP_XOR_MULT_DOSStub_fbae {
  strings:
    $key_fbae = { af c6 [2] db de [2] 9c dc [2] db cd [2] 95 c1 [2] 99 cb [2] 8e c0 [2] 95 8e [2] a8 }

  condition:
    any of them
}