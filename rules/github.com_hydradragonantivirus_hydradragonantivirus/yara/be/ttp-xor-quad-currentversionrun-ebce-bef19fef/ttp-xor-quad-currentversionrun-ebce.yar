rule TTP_XOR_QUAD_CurrentVersionRun_ebce {
  strings:
    $key_ebce = { b8 a1 [2] 9c af [2] b7 83 [2] 99 a1 [2] 8d ba [2] 82 a0 [2] 9c bd [2] 9e bc [2] 85 ba [2] 99 bd [2] 85 92 }

  condition:
    any of them
}