rule TTP_XOR_QUAD_CurrentVersionRun_2bce {
  strings:
    $key_2bce = { 78 a1 [2] 5c af [2] 77 83 [2] 59 a1 [2] 4d ba [2] 42 a0 [2] 5c bd [2] 5e bc [2] 45 ba [2] 59 bd [2] 45 92 }

  condition:
    any of them
}