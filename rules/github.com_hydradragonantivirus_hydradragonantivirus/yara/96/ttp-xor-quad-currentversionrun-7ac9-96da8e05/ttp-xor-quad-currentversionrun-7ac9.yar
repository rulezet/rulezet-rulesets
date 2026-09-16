rule TTP_XOR_QUAD_CurrentVersionRun_7ac9 {
  strings:
    $key_7ac9 = { 29 a6 [2] 0d a8 [2] 26 84 [2] 08 a6 [2] 1c bd [2] 13 a7 [2] 0d ba [2] 0f bb [2] 14 bd [2] 08 ba [2] 14 95 }

  condition:
    any of them
}