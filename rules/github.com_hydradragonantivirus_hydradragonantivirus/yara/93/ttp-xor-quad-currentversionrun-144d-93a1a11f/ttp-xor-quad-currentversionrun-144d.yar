rule TTP_XOR_QUAD_CurrentVersionRun_144d {
  strings:
    $key_144d = { 47 22 [2] 63 2c [2] 48 00 [2] 66 22 [2] 72 39 [2] 7d 23 [2] 63 3e [2] 61 3f [2] 7a 39 [2] 66 3e [2] 7a 11 }

  condition:
    any of them
}