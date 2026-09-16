rule TTP_XOR_QUAD_CurrentVersionRun_5ac9 {
  strings:
    $key_5ac9 = { 09 a6 [2] 2d a8 [2] 06 84 [2] 28 a6 [2] 3c bd [2] 33 a7 [2] 2d ba [2] 2f bb [2] 34 bd [2] 28 ba [2] 34 95 }

  condition:
    any of them
}