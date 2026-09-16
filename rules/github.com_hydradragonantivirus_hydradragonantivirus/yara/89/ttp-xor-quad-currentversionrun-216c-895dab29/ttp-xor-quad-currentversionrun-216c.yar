rule TTP_XOR_QUAD_CurrentVersionRun_216c {
  strings:
    $key_216c = { 72 03 [2] 56 0d [2] 7d 21 [2] 53 03 [2] 47 18 [2] 48 02 [2] 56 1f [2] 54 1e [2] 4f 18 [2] 53 1f [2] 4f 30 }

  condition:
    any of them
}