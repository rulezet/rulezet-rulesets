rule TTP_XOR_QUAD_CurrentVersionRun_6ac9 {
  strings:
    $key_6ac9 = { 39 a6 [2] 1d a8 [2] 36 84 [2] 18 a6 [2] 0c bd [2] 03 a7 [2] 1d ba [2] 1f bb [2] 04 bd [2] 18 ba [2] 04 95 }

  condition:
    any of them
}