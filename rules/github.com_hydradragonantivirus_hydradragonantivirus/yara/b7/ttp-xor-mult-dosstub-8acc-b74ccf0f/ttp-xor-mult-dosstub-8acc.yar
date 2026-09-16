rule TTP_XOR_MULT_DOSStub_8acc {
  strings:
    $key_8acc = { de a4 [2] aa bc [2] ed be [2] aa af [2] e4 a3 [2] e8 a9 [2] ff a2 [2] e4 ec [2] d9 }

  condition:
    any of them
}