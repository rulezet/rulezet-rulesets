rule TTP_XOR_MULT_DOSStub_8e94 {
  strings:
    $key_8e94 = { da fc [2] ae e4 [2] e9 e6 [2] ae f7 [2] e0 fb [2] ec f1 [2] fb fa [2] e0 b4 [2] dd }

  condition:
    any of them
}