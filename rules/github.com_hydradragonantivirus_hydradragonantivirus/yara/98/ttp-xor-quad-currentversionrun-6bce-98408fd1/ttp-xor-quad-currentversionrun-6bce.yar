rule TTP_XOR_QUAD_CurrentVersionRun_6bce {
  strings:
    $key_6bce = { 38 a1 [2] 1c af [2] 37 83 [2] 19 a1 [2] 0d ba [2] 02 a0 [2] 1c bd [2] 1e bc [2] 05 ba [2] 19 bd [2] 05 92 }

  condition:
    any of them
}