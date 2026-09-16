rule TTP_XOR_QUAD_CurrentVersionRun_5bce {
  strings:
    $key_5bce = { 08 a1 [2] 2c af [2] 07 83 [2] 29 a1 [2] 3d ba [2] 32 a0 [2] 2c bd [2] 2e bc [2] 35 ba [2] 29 bd [2] 35 92 }

  condition:
    any of them
}