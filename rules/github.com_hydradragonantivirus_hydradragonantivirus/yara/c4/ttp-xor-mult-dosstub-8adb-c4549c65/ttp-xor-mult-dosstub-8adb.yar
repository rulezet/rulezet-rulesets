rule TTP_XOR_MULT_DOSStub_8adb {
  strings:
    $key_8adb = { de b3 [2] aa ab [2] ed a9 [2] aa b8 [2] e4 b4 [2] e8 be [2] ff b5 [2] e4 fb [2] d9 }

  condition:
    any of them
}