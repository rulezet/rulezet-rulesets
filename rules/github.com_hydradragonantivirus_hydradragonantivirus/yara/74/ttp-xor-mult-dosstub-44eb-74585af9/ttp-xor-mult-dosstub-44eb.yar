rule TTP_XOR_MULT_DOSStub_44eb {
  strings:
    $key_44eb = { 10 83 [2] 64 9b [2] 23 99 [2] 64 88 [2] 2a 84 [2] 26 8e [2] 31 85 [2] 2a cb [2] 17 }

  condition:
    any of them
}