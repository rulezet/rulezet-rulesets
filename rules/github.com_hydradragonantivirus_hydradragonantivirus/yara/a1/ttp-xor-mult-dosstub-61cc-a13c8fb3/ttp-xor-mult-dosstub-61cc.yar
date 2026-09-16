rule TTP_XOR_MULT_DOSStub_61cc {
  strings:
    $key_61cc = { 35 a4 [2] 41 bc [2] 06 be [2] 41 af [2] 0f a3 [2] 03 a9 [2] 14 a2 [2] 0f ec [2] 32 }

  condition:
    any of them
}