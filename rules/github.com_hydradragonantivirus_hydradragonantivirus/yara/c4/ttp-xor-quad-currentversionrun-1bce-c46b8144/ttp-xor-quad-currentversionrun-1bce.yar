rule TTP_XOR_QUAD_CurrentVersionRun_1bce {
  strings:
    $key_1bce = { 48 a1 [2] 6c af [2] 47 83 [2] 69 a1 [2] 7d ba [2] 72 a0 [2] 6c bd [2] 6e bc [2] 75 ba [2] 69 bd [2] 75 92 }

  condition:
    any of them
}