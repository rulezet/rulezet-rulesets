rule TTP_XOR_QUAD_CurrentVersionRun_5bda {
  strings:
    $key_5bda = { 08 b5 [2] 2c bb [2] 07 97 [2] 29 b5 [2] 3d ae [2] 32 b4 [2] 2c a9 [2] 2e a8 [2] 35 ae [2] 29 a9 [2] 35 86 }

  condition:
    any of them
}