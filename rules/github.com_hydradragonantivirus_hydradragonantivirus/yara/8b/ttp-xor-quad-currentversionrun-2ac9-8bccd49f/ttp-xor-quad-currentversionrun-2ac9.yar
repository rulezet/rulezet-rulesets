rule TTP_XOR_QUAD_CurrentVersionRun_2ac9 {
  strings:
    $key_2ac9 = { 79 a6 [2] 5d a8 [2] 76 84 [2] 58 a6 [2] 4c bd [2] 43 a7 [2] 5d ba [2] 5f bb [2] 44 bd [2] 58 ba [2] 44 95 }

  condition:
    any of them
}