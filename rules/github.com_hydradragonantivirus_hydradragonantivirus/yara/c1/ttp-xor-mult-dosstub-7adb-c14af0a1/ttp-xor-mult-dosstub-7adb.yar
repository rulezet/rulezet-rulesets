rule TTP_XOR_MULT_DOSStub_7adb {
  strings:
    $key_7adb = { 2e b3 [2] 5a ab [2] 1d a9 [2] 5a b8 [2] 14 b4 [2] 18 be [2] 0f b5 [2] 14 fb [2] 29 }

  condition:
    any of them
}