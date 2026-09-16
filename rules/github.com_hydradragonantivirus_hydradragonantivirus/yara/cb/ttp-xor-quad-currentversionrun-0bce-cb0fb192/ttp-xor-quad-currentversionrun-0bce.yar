rule TTP_XOR_QUAD_CurrentVersionRun_0bce {
  strings:
    $key_0bce = { 58 a1 [2] 7c af [2] 57 83 [2] 79 a1 [2] 6d ba [2] 62 a0 [2] 7c bd [2] 7e bc [2] 65 ba [2] 79 bd [2] 65 92 }

  condition:
    any of them
}