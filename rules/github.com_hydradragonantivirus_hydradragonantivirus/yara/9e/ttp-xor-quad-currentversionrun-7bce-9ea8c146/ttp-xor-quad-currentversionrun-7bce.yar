rule TTP_XOR_QUAD_CurrentVersionRun_7bce {
  strings:
    $key_7bce = { 28 a1 [2] 0c af [2] 27 83 [2] 09 a1 [2] 1d ba [2] 12 a0 [2] 0c bd [2] 0e bc [2] 15 ba [2] 09 bd [2] 15 92 }

  condition:
    any of them
}