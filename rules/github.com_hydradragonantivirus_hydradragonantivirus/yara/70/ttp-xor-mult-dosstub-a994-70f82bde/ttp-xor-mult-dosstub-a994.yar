rule TTP_XOR_MULT_DOSStub_a994 {
  strings:
    $key_a994 = { fd fc [2] 89 e4 [2] ce e6 [2] 89 f7 [2] c7 fb [2] cb f1 [2] dc fa [2] c7 b4 [2] fa }

  condition:
    any of them
}