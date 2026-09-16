rule TTP_XOR_MULT_DOSStub_9866 {
  strings:
    $key_9866 = { cc 0e [2] b8 16 [2] ff 14 [2] b8 05 [2] f6 09 [2] fa 03 [2] ed 08 [2] f6 46 [2] cb }

  condition:
    any of them
}