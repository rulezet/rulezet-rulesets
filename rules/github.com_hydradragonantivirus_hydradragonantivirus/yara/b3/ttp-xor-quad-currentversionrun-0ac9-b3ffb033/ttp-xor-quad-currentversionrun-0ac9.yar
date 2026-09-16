rule TTP_XOR_QUAD_CurrentVersionRun_0ac9 {
  strings:
    $key_0ac9 = { 59 a6 [2] 7d a8 [2] 56 84 [2] 78 a6 [2] 6c bd [2] 63 a7 [2] 7d ba [2] 7f bb [2] 64 bd [2] 78 ba [2] 64 95 }

  condition:
    any of them
}