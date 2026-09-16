rule TTP_XOR_QUAD_CurrentVersionRun_2171 {
  strings:
    $key_2171 = { 72 1e [2] 56 10 [2] 7d 3c [2] 53 1e [2] 47 05 [2] 48 1f [2] 56 02 [2] 54 03 [2] 4f 05 [2] 53 02 [2] 4f 2d }

  condition:
    any of them
}