rule TTP_XOR_QUAD_CurrentVersionRun_e36d {
  strings:
    $key_e36d = { b0 02 [2] 94 0c [2] bf 20 [2] 91 02 [2] 85 19 [2] 8a 03 [2] 94 1e [2] 96 1f [2] 8d 19 [2] 91 1e [2] 8d 31 }

  condition:
    any of them
}