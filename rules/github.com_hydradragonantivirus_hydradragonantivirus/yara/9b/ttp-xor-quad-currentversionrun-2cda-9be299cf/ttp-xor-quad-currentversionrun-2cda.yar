rule TTP_XOR_QUAD_CurrentVersionRun_2cda {
  strings:
    $key_2cda = { 7f b5 [2] 5b bb [2] 70 97 [2] 5e b5 [2] 4a ae [2] 45 b4 [2] 5b a9 [2] 59 a8 [2] 42 ae [2] 5e a9 [2] 42 86 }

  condition:
    any of them
}